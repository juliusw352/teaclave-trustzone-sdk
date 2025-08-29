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

#![no_main]

mod attester;
mod endorsement_store;
mod endorser;
mod pta_command;

use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::property::{ClientIdentity, PropertyKey};
use optee_utee::{Error, ErrorKind, Parameters, Result};

use attestation::{Attester, Endorser, Identity, Quote, Quoter, UserData};
use quoting_ta_proto::{QuotingTaCommand, QUOTING_TA_UUID};

use std::convert::TryFrom;

use crate::attester::{EcdsaAttestationKeyManager, PtaAttester};
use crate::endorsement_store::LocalEndorsementStore;
use crate::endorser::{EcdsaPlatformKeyManager, QuotingTaReportVerifier};

fn get_quote(target_ta: &Identity, user_data: UserData) -> anyhow::Result<Quote> {
    trace_println!("[+] Getting quote for target TA: {:?}", target_ta);
    // Initialize components
    let ak_manager = EcdsaAttestationKeyManager::init()?;
    trace_println!("[+] AK manager initialized");
    let ta_measuring = PtaAttester;
    let platform_key_manager = EcdsaPlatformKeyManager::init()?;
    trace_println!("[+] Platform key manager initialized");
    let endorsement_store = LocalEndorsementStore::init()?;
    trace_println!("[+] Endorsement store initialized");
    let quoting_ta_report_verifier = QuotingTaReportVerifier;
    trace_println!("[+] Components initialized");

    // Create attester and endorser
    let attester = Attester::new(ak_manager, ta_measuring);
    let endorser = Endorser::new(platform_key_manager, quoting_ta_report_verifier);

    // Create quoter with this TA's identity
    let quoter_identity = Identity::try_from(QUOTING_TA_UUID.to_string())?;
    let quoter = Quoter::new(quoter_identity, attester, endorser, endorsement_store);
    trace_println!("[+] Quoter initialized");

    // Get quote
    let quote = quoter.get_quote(target_ta, user_data)?;
    trace_println!("[+] Quote generated successfully");

    Ok(quote)
}

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] Quoting TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters) -> Result<()> {
    trace_println!("[+] Quoting TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session() {
    trace_println!("[+] Quoting TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] Quoting TA destroy");
}

#[ta_invoke_command]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] Quoting TA invoke command");
    match QuotingTaCommand::from(cmd_id) {
        QuotingTaCommand::GetQuote => {
            trace_println!("[+] Get Quote command invoked");
            // Get Quote command
            let mut p0 = unsafe { params.0.as_memref().unwrap() };
            let mut p1 = unsafe { params.1.as_memref().unwrap() };

            // Get user data from input parameter
            let user_data = UserData::try_from(p0.buffer().to_vec()).map_err(|e| {
                trace_println!("[-] Failed to get user data: {:?}", e);
                Error::new(ErrorKind::BadParameters)
            })?;
            trace_println!("[+] User data: {:?}", user_data);

            // Get target TA identity (current client)
            let target_ta_uuid = ClientIdentity.get()?.uuid().to_string();
            trace_println!("[+] Target TA UUID: {:?}", target_ta_uuid);
            // Convert UUID to Identity
            let target_ta = Identity::try_from(target_ta_uuid).map_err(|e| {
                trace_println!("[-] Failed to get target TA identity: {:?}", e);
                Error::new(ErrorKind::BadParameters)
            })?;
            trace_println!("[+] Target TA identity: {:?}", target_ta);

            // Get quote
            let quote = get_quote(&target_ta, user_data).map_err(|e| {
                trace_println!("[-] Failed to get quote: {:?}", e);
                Error::new(ErrorKind::Generic)
            })?;
            trace_println!("[+] Quote generated: {:?}", quote);

            // Serialize quote and write to output parameter
            let serialized_quote = bincode::serialize(&quote).map_err(|e| {
                trace_println!("[-] Failed to serialize quote: {:?}", e);
                Error::new(ErrorKind::BadParameters)
            })?;
            trace_println!("[+] Serialized quote len: {:?}", serialized_quote.len());

            p1.buffer()[..serialized_quote.len()].copy_from_slice(&serialized_quote);
            trace_println!("[+] Quote written to output buffer");
            Ok(())
        }
        _ => Err(Error::new(ErrorKind::NotSupported)),
    }
}

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
