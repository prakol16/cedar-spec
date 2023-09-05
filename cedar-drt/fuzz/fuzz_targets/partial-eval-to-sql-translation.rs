/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use cedar_db::dump_entities;
use cedar_drt::initialize_log;
use cedar_policy::PartialValue;
use cedar_policy_generators::{schema::Schema, abac::{ABACPolicy, ABACRequest}, settings::ABACSettings, hierarchy::HierarchyGenerator};
use libfuzzer_sys::{arbitrary::{self, Arbitrary, Unstructured}, fuzz_target};
use cedar_policy_core::{entities::{Entities, TCComputation}, authorizer::Authorizer, extensions::Extensions};
use cedar_policy_core::ast;
use log::debug;
use postgres::{NoTls, Client, error::SqlState};


/// Input expected by this fuzz target:
/// An ABAC hierarchy, policy, and 8 associated requests
#[derive(Debug, Clone)]
struct FuzzTargetInput {
    /// generated schema
    pub schema: Schema,
    /// generated entity slice
    pub entities: Entities,
    /// generated policy
    pub policy: ABACPolicy,
    // TODO: add principal requests (requests where principal is unknown)

    /// the resource requests (requests where resource is unknown)
    /// to try for this hierarchy and policy
    pub resource_requests: [ast::Request; 4],
}

/// settings for this fuzz target
const SETTINGS: ABACSettings = ABACSettings {
    match_types: true,
    enable_extensions: false,
    max_depth: 3,
    max_width: 3,
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

        let resource_requests = [
            schema.arbitrary_resource_request(&hierarchy, u)?,
            schema.arbitrary_resource_request(&hierarchy, u)?,
            schema.arbitrary_resource_request(&hierarchy, u)?,
            schema.arbitrary_resource_request(&hierarchy, u)?,
        ];
        let all_entities = Entities::try_from(hierarchy).map_err(|_| arbitrary::Error::NotEnoughData)?;
        let entities = drop_some_entities(all_entities, u)?;
        Ok(Self {
            schema,
            entities,
            policy,
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

const DB_PATH: &str = "host=localhost user=postgres dbname=db_fuzzer password=postgres";

/// Suppress certain postgres errors that we intentionally ignore
/// Returns None if we should ignore the error
/// Panics if we should not ignore the error
fn suppress_postgres_error<T>(v: Result<T, postgres::Error>, while_msg: &str) -> Option<T> {
    match v {
        Ok(v) => Some(v),
        Err(e) => {
            if let Some(e) = e.as_db_error() {
                if e.code() == &SqlState::CHARACTER_NOT_IN_REPERTOIRE && e.message().contains("0x00") {
                    // Postgres does not support null characters in UTF-8 strings, despite it being a valid UTF-8 character
                    // This is due to the backend implementation being in C
                    // We ignore this error
                    return None;
                }
            }
            panic!("Unexpected postgres error while {}: {:?}", while_msg, e);
        }
    }
}

/// Given the entities, creates the schema "cedar" in postgres and adds the entities to the database
fn create_entities_schema(entities: &Entities<PartialValue>, schema: &cedar_policy::Schema) -> Option<()> {
    let mut conn = Client::connect(DB_PATH, NoTls)
        .expect("Postgres client should exist with a user 'postgres', password 'postgres', and database 'db_fuzzer'");
    conn.batch_execute(r#"DROP SCHEMA IF EXISTS "cedar" CASCADE; CREATE SCHEMA "cedar""#)
        .expect("schema 'cedar' should be creatable");
    let stmts = dump_entities::create_tables_postgres(entities, schema)
        .expect("schema should be creatable")
        .join(";");

    debug!("Running postgres query: {}", stmts);
    suppress_postgres_error(conn.batch_execute(&stmts), "creating and populating entities schema")?;
    Some(())
}

/// Check that partial evaluation + sql query gives the same result as
/// evaluating on every concrete principal/resource
/// Returns None if there was an early exit (e.g. typechecking failed,
/// nested sets which could not be translated)
/// TODO: collect statistics about how frequently there are early exits
fn do_test(input: FuzzTargetInput) -> Option<()> {
    let mut policyset = ast::PolicySet::new();
    policyset.add_static(input.policy.into()).unwrap();
    debug!("Schema: {}\n", input.schema.schemafile_string());
    debug!("Policies: {policyset}\n");

    let schema: cedar_policy::Schema = cedar_policy::Schema(input.schema.try_into().ok()?);


    let exts = Extensions::none();
    let entities_evaled = input.entities.eval_attrs(&exts).ok()?;

    // create the entities schema in postgres
    create_entities_schema(&entities_evaled, &schema)?;

    Some(())
}

// The main fuzz target. This is for type-directed fuzzing of ABAC
// hierarchy/policy/requests
fuzz_target!(|input: FuzzTargetInput| {
    initialize_log();
    do_test(input);
});

