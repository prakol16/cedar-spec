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

use cedar_db::{dump_entities::{EntityTableIden, EntityAncestryTableIden, AncestryCols}, query_builder::translate_response_core, expr_to_query::InByTable, sql_common::EntitySQLId};
use cedar_drt::initialize_log;
use cedar_policy::{PartialValue, EntityTypeName, Decision};
use cedar_policy_generators::{schema::Schema, abac::ABACPolicy, settings::ABACSettings, hierarchy::HierarchyGenerator, collections::{HashSet, HashMap}};
use libfuzzer_sys::{arbitrary::{self, Arbitrary, Unstructured}, fuzz_target};
use cedar_policy_core::{entities::{Entities, TCComputation}, authorizer::{Authorizer, ResponseKind}, extensions::Extensions, ast::{PolicySet, EntityUID}};
use cedar_policy_core::ast;
use log::debug;
use postgres::Client;
use smol_str::SmolStr;
use cedar_drt_inner::sql::*;
// use ref_cast::RefCast;

/// Input expected by this fuzz target:
/// An ABAC hierarchy, policy, and 4 associated requests
#[derive(Debug, Clone)]
struct FuzzTargetInput {
    /// generated schema
    pub schema: Schema,
    /// generated entity slice
    pub entities: Entities,
    /// generated policy
    pub policy: ABACPolicy,

    /// the resource requests (requests where resource is unknown)
    /// to try for this hierarchy and policy
    pub resource_requests: [ast::Request; 2],

    /// the principal requests (requests where principal is unknown)
    /// to try for this hierarchy and policy
    pub principal_requests: [ast::Request; 2]
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
    enable_unknowns: false,
};


impl<'a> Arbitrary<'a> for FuzzTargetInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let schema = Schema::arbitrary(SETTINGS.clone(), u)?;
        let hierarchy = schema.arbitrary_hierarchy(u)?;
        let policy = schema.arbitrary_policy(&hierarchy, u)?;
        let principal_requests = [
            schema.arbitrary_principal_request(&hierarchy, u)?,
            schema.arbitrary_principal_request(&hierarchy, u)?,
        ];
        let resource_requests = [
            schema.arbitrary_resource_request(&hierarchy, u)?,
            schema.arbitrary_resource_request(&hierarchy, u)?,
        ];
        let all_entities = Entities::try_from(hierarchy).map_err(|_| arbitrary::Error::NotEnoughData)?;
        let entities = drop_some_entities(all_entities, u)?;
        Ok(Self {
            schema,
            entities,
            policy,
            principal_requests,
            resource_requests,
        })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and_all(&[
            Schema::arbitrary_size_hint(depth),
            HierarchyGenerator::size_hint(depth),
            Schema::arbitrary_policy_size_hint(&SETTINGS, depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            // Schema::arbitrary_request_size_hint(depth),
            // Schema::arbitrary_request_size_hint(depth),
            // Schema::arbitrary_request_size_hint(depth),
            // Schema::arbitrary_request_size_hint(depth),
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

/// Check that the entities returned by the query that comes from translating the response `res`
/// are precisely the entities in the set `allow_set`
fn check_residual_query_eq_allowed_set(
    ty: &ast::Name, // the type of entity being queried
    res: &cedar_policy_core::authorizer::PartialResponse,
    schema: &cedar_policy::Schema,
    id_map: &HashMap<EntityTypeName, SmolStr>,
    allow_set: HashSet<EntityUID>,
    conn: &mut Client
) -> Option<()> {
    let result = translate_response_core(
        res,
        schema,
        // Given two entity types ty0 and ty1, return the table that holds their relationship
        InByTable(|ty0, ty1| {
            if schema.can_be_descendant(ty0, ty1) {
                Ok(Some((
                    EntityAncestryTableIden::new(ty0.clone(), ty1.clone()),
                    AncestryCols::Descendant,
                    AncestryCols::Ancestor,
                )))
            } else {
                Ok(None)
            }
        }),
        // Given an entity type, return the corresponding table name and id column
        |ty| {
            (EntityTableIden::new(ty.clone()), id_map.get(ty)
                .expect("Id map should have an id for every entity in the schema")
                .clone())
        }
    );

    match result {
        Ok(mut result) => {
            result.query_default()
                .unwrap_or_else(|_| panic!("There is not a single unique unknown in the query {:?}", result));
            let query = result.to_string_postgres();
            if query.contains('\0') {
                // Postgres does not support null characters in UTF-8 strings, despite it being a valid UTF-8 character
                // This is due to the backend implementation being in C
                // We ignore this error
                return None;
            }
            let rows = suppress_postgres_error(conn.query(&query, &[]),
                || format!("querying postgres with query {}", query))?;

            let rows_set = rows.into_iter().map(|row| {
                let id: EntitySQLId = row.get(0);
                // todo: entity id -> eid conversion
                EntityUID::from_components(ty.clone(), ast::Eid::new(id.id().as_ref()))
            }).collect::<HashSet<_>>();
            if rows_set != allow_set {
                panic!("The resources returned by the sql query {} are {:?}; does not match the resources returned by the partial evaluation {:?}", query, rows_set, allow_set);
            }
            Some(())
        },
        Err(err) => {
            if is_expected_error(&err) {
                None
            } else {
                panic!("Unexpected error while translating response {} to sql query: {:?}", res.residuals.get(&ast::PolicyID::from_string("")).unwrap().to_string(), err)
            }
        }
    }
}

/// Check that the resources which satisfy a request q are precisely the
/// resources that are returned by the translated sql query
/// Note: if the request fails on any resource OR if the translation fails with certain errors, then
/// we do no test and return None
fn match_resource_request(q: ast::Request, entities: &Entities<PartialValue>, schema: &cedar_policy::Schema, pset: &PolicySet, id_map: &HashMap<EntityTypeName, SmolStr>, conn: &mut Client) -> Option<()> {
    let ty0 = q.resource().type_name()?;
    let ty1 = match &ty0 {
        ast::EntityType::Concrete(ty) => ty,
        ast::EntityType::Unspecified => return None,
    };
    // let ty2 = EntityTypeName::ref_cast(ty1);

    let auth = Authorizer::new();
    let mut allowed_resources: HashSet<EntityUID> = HashSet::new();

    for entity in entities.iter() {
        let uid = entity.uid();
        if uid.entity_type() == &ty0 {
            let q1 = ast::Request::new_with_unknowns(
                q.principal().clone(),
                q.action().clone(),
                ast::EntityUIDEntry::concrete(uid.clone()),
                q.context().cloned()
            );
            let is_auth = auth.is_authorized_parsed(&q1, pset, entities);
            if !is_auth.diagnostics.errors.is_empty() {
                return None;
            }
            if is_auth.decision == Decision::Allow {
                allowed_resources.insert(uid);
            }
        }
    }

    let partial_response = auth.is_authorized_core_parsed(&q, pset, entities);
    match partial_response {
        ResponseKind::FullyEvaluated(_) => None,
        ResponseKind::Partial(res) => {
            check_residual_query_eq_allowed_set(ty1, &res, schema, id_map, allowed_resources, conn)
        }
    }
}

/// Check that the principals which satisfy a request q are precisely the
/// resources that are returned by the translated sql query
/// Note: if the request fails on any resource OR if the translation fails with certain errors, then
/// we do no test and return None
fn match_principal_request(q: ast::Request, entities: &Entities<PartialValue>, schema: &cedar_policy::Schema, pset: &PolicySet, id_map: &HashMap<EntityTypeName, SmolStr>, conn: &mut Client) -> Option<()> {
    let ty0 = q.principal().type_name()?;
    let ty1 = match &ty0 {
        ast::EntityType::Concrete(ty) => ty,
        ast::EntityType::Unspecified => return None,
    };

    let auth = Authorizer::new();
    let mut allowed_principals: HashSet<EntityUID> = HashSet::new();

    for entity in entities.iter() {
        let uid = entity.uid();
        if uid.entity_type() == &ty0 {
            let q1 = ast::Request::new_with_unknowns(
                ast::EntityUIDEntry::concrete(uid.clone()),
                q.action().clone(),
                q.resource().clone(),
                q.context().cloned()
            );
            let is_auth = auth.is_authorized_parsed(&q1, pset, entities);
            if !is_auth.diagnostics.errors.is_empty() {
                return None;
            }
            if is_auth.decision == Decision::Allow {
                allowed_principals.insert(uid);
            }
        }
    }

    let partial_response = auth.is_authorized_core_parsed(&q, pset, entities);
    match partial_response {
        ResponseKind::FullyEvaluated(_) => None,
        ResponseKind::Partial(res) => {
            check_residual_query_eq_allowed_set(ty1, &res, schema, id_map, allowed_principals, conn)
        }
    }
}

/// Check that partial evaluation + sql query gives the same result as
/// evaluating on every concrete principal/resource
/// Returns None if there was an early exit (e.g. typechecking failed,
/// nested sets which could not be translated)
/// TODO: collect statistics about how frequently there are early exits
fn do_test(input: FuzzTargetInput) -> Option<()> {
    let mut conn = get_conn();

    let mut policyset = ast::PolicySet::new();
    policyset.add_static(input.policy.into()).unwrap();
    debug!("Schema: {}\n", input.schema.schemafile_string());
    debug!("Policies: {policyset}\n");

    let schema: cedar_policy::Schema = cedar_policy::Schema(input.schema.try_into().ok()?);

    let exts = Extensions::none();
    let entities_evaled = input.entities.eval_attrs(&exts).ok()?;

    // create the entities schema in postgres
    let id_map = create_entities_schema(&entities_evaled, &schema, &mut conn)?;

    for q in input.principal_requests {
        match_principal_request(q, &entities_evaled, &schema, &policyset, &id_map, &mut conn);
    }

    for q in input.resource_requests {
        match_resource_request(q, &entities_evaled, &schema, &policyset, &id_map, &mut conn);
    }

    Some(())
}

// The main fuzz target. This is for type-directed fuzzing of ABAC
// hierarchy/policy/requests
fuzz_target!(|input: FuzzTargetInput| {
    initialize_log();
    // TODO: log whether do_test returned Some(()) or None
    // to keep track of how many tests actually go "all the way"
    do_test(input);
});

