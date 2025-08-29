// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#![no_std]
use num_enum::{FromPrimitive, IntoPrimitive};

pub const MAX_OUTPUT_SIZE: usize = 4096;

// Quoting TA (Rust): part of the SDK
// Return the Quote to the App TA
// 1. get Identity(uuid, is_user_ta) of caller TA (App TA)
// 2. prepare attestation_pubkey, and sign it by endorser
// 3. invoke Attestation PTA to get attestation report for caller TA
// 4. concatenate the Quote and return to caller TA
#[derive(FromPrimitive, IntoPrimitive, Default)]
#[repr(u32)]
pub enum QuotingTaCommand {
    // param[0] memref_in: nonce
    // param[1] memref_out: serialized(Quote)
    GetQuote,
    #[default]
    Unknown,
}

pub const QUOTING_TA_UUID: &str = &include_str!("../../quoting_ta_uuid.txt");
