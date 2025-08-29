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

use num_enum::{FromPrimitive, IntoPrimitive};

pub const MAX_OUTPUT_SIZE: usize = 4096;

// AttestationPta (C): part of the OP-TEE OS
// duplicated from attestation_pta.c and modify the following:
// 1. get Identity(uuid, is_user_ta) of caller, caller should be Quoting TA
// 2. get os_hash, target_ta_binary_hash and target_ta_mem_hash
// 3. return ReportBody to Quoting TA
#[derive(FromPrimitive, IntoPrimitive, Default)]
#[repr(u32)]
pub enum AttestationPtaCommand {
    // param[0] memref_in: target_ta_uuid
    // param[1] memref_out: encoded(ReportBody)
    GetReport = 4,
    #[default]
    Unknown,
}

pub const ATTESTATION_PTA_UUID: &str = "39800861-182a-4720-9b67-2bcd622bc0b5";
