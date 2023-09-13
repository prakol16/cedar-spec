/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![no_main]

use cedar_db::{query_expr::UnknownType, query_builder::translate_expr_to_expr_with_bindings, dump_entities::{EntityTableIden, EntityAncestryTableIden, AncestryCols, CedarSQLSchemaName}, expr_to_query::InByTable};
use cedar_drt::initialize_log;
use cedar_drt_inner::sql::{get_conn, create_entities_schema, create_unknown_pool, UnknownPoolIden};
use cedar_policy::{PartialValue, Value, EntityTypeName};
use cedar_policy_generators::{schema::Schema, abac::{Type, ABACRequest}, settings::ABACSettings, hierarchy::HierarchyGenerator, collections::HashMap};
use cedar_policy_core::{entities::{Entities, TCComputation, EntityAttrDatabase}, extensions::Extensions, evaluator::Evaluator, ast::{Expr, Literal, EntityType}};
use cedar_policy_core::ast;
use libfuzzer_sys::{fuzz_target, arbitrary::{Arbitrary, Unstructured, self}};
use postgres::Client;
use ref_cast::RefCast;
use sea_query::PostgresQueryBuilder;
use smol_str::SmolStr;


/// Input expected by this fuzz target:
/// An ABAC hierarchy, policy, and 4 associated requests
#[derive(Debug, Clone)]
struct FuzzTargetInput {
    /// generated schema
    pub schema: Schema,
    /// generated entity slice
    pub entities: Entities,
    /// generated expression
    pub expr: ast::Expr,
    /// requests which the expression will be evaluated against
    pub requests: [ABACRequest; 8],
}

/// settings for this fuzz target
const SETTINGS: ABACSettings = ABACSettings {
    match_types: true,
    enable_extensions: false,
    max_depth: 7,
    max_width: 7,
    enable_additional_attributes: false,
    enable_like: true,
    enable_action_groups_and_attrs: true,
    enable_arbitrary_func_call: false,
    enable_unknowns: true,
};

impl<'a> Arbitrary<'a> for FuzzTargetInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let schema = Schema::arbitrary(SETTINGS.clone(), u)?;
        let hierarchy = schema.arbitrary_hierarchy(u)?;
        let exprgenerator = schema.exprgenerator(Some(&hierarchy));
        let ty = Type::arbitrary(u)?;
        let expr = exprgenerator.generate_expr_for_type(
            &ty,
            schema.settings.max_depth,
            u,
        )?;
        let requests = [
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
        ];

        let all_entities = Entities::try_from(hierarchy).map_err(|_| arbitrary::Error::NotEnoughData)?;
        let entities = drop_some_entities(all_entities, u)?;
        Ok(Self { schema, entities, expr, requests })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and_all(&[
            Schema::arbitrary_size_hint(depth),
            HierarchyGenerator::size_hint(depth),
            Schema::arbitrary_policy_size_hint(&SETTINGS, depth),
            Type::size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
        ])
    }
}


fn drop_some_entities(entities: Entities, u: &mut Unstructured<'_>) -> arbitrary::Result<Entities> {
    let should_drop: bool = u.arbitrary()?;
    if should_drop {
        let mut set: Vec<_> = vec![];
        for entity in entities.iter() {
            match u.int_in_range(0..=9)? {
                0 => (),
                _ => {
                    set.push(entity.clone());
                }
            }
        }
        Ok(
            Entities::from_entities(set.into_iter(), TCComputation::AssumeAlreadyComputed)
                .expect("Should be valid"),
        )
    } else {
        Ok(entities)
    }
}

/// Checks that the given expression, when evaluated, results in the same value
/// as if we translate the expression to SQL and evaluate it in postgres.
fn check_expr<T: EntityAttrDatabase>(
    e: &Expr,
    evaluator: &Evaluator<'_, T>,
    substitutions: &HashMap<SmolStr, Value>,
    renamings: &HashMap<UnknownType, UnknownType>,
    schema: &cedar_policy::Schema,
    id_map: &HashMap<EntityTypeName, SmolStr>,
    conn: &mut Client,
) -> Option<()> {
    let subst = e.substitute(&substitutions.clone().into())
        .expect("Substitutions should suceeed");

    let _ = evaluator.interpret(&subst, &Default::default())
        .expect("Evaluation should succeed");

    // Now, convert the original expression to a SQL expression, evaluate it, and check that
    // the result is the same as the full evaluation
    let table_names = |ty: &EntityTypeName| {
        (EntityTableIden::new(ty.clone()), id_map.get(ty)
                .expect("Id map should have an id for every entity in the schema")
                .clone())
    };
    let expr_with_bindings =
        translate_expr_to_expr_with_bindings(e, schema, table_names, &renamings.clone().into())
        .expect("Translation should succeed");
    let mut sql = expr_with_bindings.to_sql_expr_query(InByTable(|ty0, ty1| {
        if schema.can_be_descendant(ty0, ty1) {
            Ok(Some((
                EntityAncestryTableIden::new(ty0.clone(), ty1.clone()),
                AncestryCols::Descendant,
                AncestryCols::Ancestor,
            )))
        } else {
            Ok(None)
        }
    }), table_names)
        .expect("Building the query should succeed");
    sql.from_as((CedarSQLSchemaName, UnknownPoolIden), UnknownPoolIden);
    let _ = sql.to_string(PostgresQueryBuilder);



    Some(())
}

fn do_test(input: FuzzTargetInput) -> Option<()> {
    let mut conn = get_conn();
    let unk_pool = input.schema.unknown_pool.clone();
    let schema: cedar_policy::Schema = cedar_policy::Schema(input.schema.try_into().ok()?);

    let exts = Extensions::none();
    let entities_evaled = input.entities.eval_attrs(&exts).ok()?;

    // create the entities schema in postgres
    let id_map = create_entities_schema(&entities_evaled, &schema, &mut conn)?;
    // add the unknown pool to the schema as well
    create_unknown_pool(unk_pool.clone(), &mut conn)?;

    let mut substitutions: HashMap<SmolStr, Value> = HashMap::new();
    let mut renamings: HashMap<UnknownType, UnknownType> = HashMap::new();
    for (unk, v) in unk_pool.mapping() {
        let unk = SmolStr::from(unk);
        let ety = if let Value::Lit(Literal::EntityUID(uid)) = &v {
            if let EntityType::Concrete(ety) = uid.entity_type() {
                Some(EntityTypeName::ref_cast(ety).clone())
            } else { None }
        } else { None };
        renamings.insert(UnknownType::of_name_and_type(unk.clone(), ety),
            UnknownType::NonEntityType { pfx: Some("unknown_pool".into()), name: unk.clone() });
        substitutions.insert(unk.clone(), v);
    }

    let extns = Extensions::none();
    for q in input.requests {
        let eval = Evaluator::new(&q.0.into(), &entities_evaled, &extns).ok()?;
        match eval.partial_interpret(&input.expr, &Default::default()).ok()? {
            PartialValue::Value(_) => None,
            PartialValue::Residual(e) => {
                check_expr(&e, &eval, &substitutions, &renamings, &schema, &id_map, &mut conn)
            },
        };
    }

    Some(())
}

// The main fuzz target.
fuzz_target!(|input: FuzzTargetInput| {
    initialize_log();
    do_test(input);
});
