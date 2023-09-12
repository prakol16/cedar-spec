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

use cedar_drt::initialize_log;
use cedar_policy_generators::{schema::Schema, abac::ABACPolicy, settings::ABACSettings, hierarchy::HierarchyGenerator, collections::{HashSet, HashMap}};
use cedar_policy_core::{entities::{Entities, TCComputation}, authorizer::{Authorizer, ResponseKind}, extensions::Extensions, ast::{PolicySet, EntityUID}};
use cedar_policy_core::ast;
use libfuzzer_sys::{fuzz_target, arbitrary::{Arbitrary, Unstructured, self}};


/// Input expected by this fuzz target:
/// An ABAC hierarchy, policy, and 4 associated requests
#[derive(Debug, Clone)]
struct FuzzTargetInput {
    /// generated schema
    pub schema: Schema,
    /// generated entity slice
    pub entities: Entities,
}


impl<'a> Arbitrary<'a> for FuzzTargetInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        todo!()
    }
}

fn do_test(input: FuzzTargetInput) -> Option<()> {
    None
}

// The main fuzz target.
fuzz_target!(|input: FuzzTargetInput| {
    initialize_log();
    do_test(input);
});
