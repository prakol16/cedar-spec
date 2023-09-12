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

use cedar_db::{
    dump_entities::{self, DumpEntitiesError},
    query_expr::QueryExprError,
};
use cedar_policy::{EntityTypeName, PartialValue};
use cedar_policy_core::entities::Entities;
use cedar_policy_generators::collections::HashMap;
use log::debug;
use postgres::{error::SqlState, Client, NoTls};
use smol_str::SmolStr;

pub const DB_PATH: &str = "host=localhost user=postgres dbname=db_fuzzer password=postgres";

pub fn get_conn() -> Client {
    Client::connect(DB_PATH, NoTls)
        .expect("Postgres client should exist with a user 'postgres', password 'postgres', and database 'db_fuzzer'")
}

/// Suppress certain postgres errors that we intentionally ignore.
/// Returns None if we should ignore the error.
/// Panics if we should not ignore the error.
pub fn suppress_postgres_error<T>(
    v: Result<T, postgres::Error>,
    while_msg: impl FnOnce() -> String,
) -> Option<T> {
    match v {
        Ok(v) => Some(v),
        Err(e) => {
            if let Some(e) = e.as_db_error() {
                // This should now be checked manually
                // if e.code() == &SqlState::CHARACTER_NOT_IN_REPERTOIRE && e.message().contains("0x00") {
                //     // Postgres does not support null characters in UTF-8 strings, despite it being a valid UTF-8 character
                //     // This is due to the backend implementation being in C
                //     // We ignore this error
                //     return None;
                // }
                if e.code() == &SqlState::UNTRANSLATABLE_CHARACTER
                    && e.detail().is_some()
                    && e.detail().unwrap().contains(r#"\u0000"#)
                {
                    // Same as above error, but this one seems to get reported when the error is thrown while parsing JSON
                    // We ignore this error
                    return None;
                }
                if e.code() == &SqlState::FOREIGN_KEY_VIOLATION {
                    // We ignore this error because sometimes the generator generates entity stores
                    // with uids that do not exist; we purposefully ignore this situation
                    return None;
                }
                // if empty_array && e.code() == &SqlState::INDETERMINATE_DATATYPE && e.message() == "cannot determine type of empty array" {
                //     // Seaquery has a bug where it does not convert empty arrays correctly
                //     // See https://github.com/SeaQL/sea-query/issues/693
                //     return None;
                // }
            }
            panic!("Unexpected postgres error while {}: {:?}", while_msg(), e);
        }
    }
}

/// Suppress certain dumpentities errors that we intentionally ignore.
/// Returns None if we should ignore the error.
/// Panics if we should not ignore the error.
fn suppress_dumpentities_error<T>(
    v: Result<T, DumpEntitiesError>,
    while_msg: impl FnOnce() -> String,
) -> Option<T> {
    match v {
        Ok(v) => Some(v),
        Err(e) => {
            if &e == &DumpEntitiesError::QueryExprError(QueryExprError::NestedSetsError) {
                // We ignore this error because we explicitly do not support nested sets
                return None;
            }
            if matches!(e, DumpEntitiesError::IdentifierTooLong(_)) {
                // It's too difficult to prevent long identifiers from being generated
                // so we just ignore the error
                return None;
            }
            panic!(
                "Unexpected DumpEntitiesError while {}: {:?}",
                while_msg(),
                e
            );
        }
    }
}

/// Given the entities, creates the schema "cedar" in postgres and adds the entities to the database
/// Returns the id map that was used to create the schema
pub fn create_entities_schema(
    entities: &Entities<PartialValue>,
    schema: &cedar_policy::Schema,
    conn: &mut Client,
) -> Option<HashMap<EntityTypeName, SmolStr>> {
    conn.batch_execute(r#"DROP SCHEMA IF EXISTS "cedar" CASCADE; CREATE SCHEMA "cedar""#)
        .expect("schema 'cedar' should be creatable");
    let (stmts, id_map) = suppress_dumpentities_error(
        dump_entities::create_tables_postgres(entities, schema),
        || "creating schema query statements".into(),
    )?;
    debug!("Running postgres query: {:?}", stmts);
    let stmts_joined = stmts.join(";");
    if stmts_joined.contains('\0') {
        // Postgres does not support null characters in UTF-8 strings, despite it being a valid UTF-8 character
        // This is due to the backend implementation being in C
        // We ignore this error
        return None;
    }
    suppress_postgres_error(conn.batch_execute(&stmts.join(";")), || {
        format!(
            "creating and populating entities schema using query {}",
            stmts.join(";")
        )
    })?;
    Some(id_map.into())
}
