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
#![no_main]
extern crate alloc;

use attestation_forwarder::QuotingTaClient;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result, Uuid};
use proto::Command;
use quoting_ta_proto::QUOTING_TA_UUID;

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] App TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters) -> Result<()> {
    trace_println!("[+] App TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session() {
    trace_println!("[+] App TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] App TA destroy");
}

#[ta_invoke_command]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] App TA invoke command");
    match Command::from(cmd_id) {
        Command::GetQuote => {
            let quoting_ta_uuid =
                Uuid::parse_str(QUOTING_TA_UUID).map_err(|_| Error::new(ErrorKind::BadState))?;

            let service = QuotingTaClient::init(quoting_ta_uuid)?;
            service.get_quote(params)
        }
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
}

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
