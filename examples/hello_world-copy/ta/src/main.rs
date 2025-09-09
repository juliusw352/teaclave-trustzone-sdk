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
#![allow(clippy::needless_return)]

extern crate alloc;

use core::convert::TryInto;

use alloc::vec;
use optee_utee::Random;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::Command;

use secure_db::{SecureStorageClient, Storable};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DbDataType {
    pub id: String,
    pub data: u64,
}

impl Storable for DbDataType {
    type Key = String;

    fn unique_id(&self) -> Self::Key {
        self.id.clone()
    }
}

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session() {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}

pub fn incoming_key_compute(params: &mut Parameters) -> anyhow::Result<()> {
    // Using small prime numbers for simplicity and due to standard type restrictions in Rust;
    // in real applications, use large primes
    let p: u64 = 345466091;
    let base: u64 = 124717;

    let mut par = unsafe { params.0.as_memref().unwrap() };
    let mut buf = vec![0; par.buffer().len()];
    buf.copy_from_slice(par.buffer());

    // Receive incoming public key
    let incoming_public_key: u64 = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
    trace_println!(
        "[+] TA received incoming public key: {}",
        incoming_public_key
    );

    // Generate public/secret key pair
    Random::generate(buf.as_mut() as _);
    let secret_key: u64 = u64::from_ne_bytes(buf[0..8].try_into().unwrap()) % (p - 1);
    trace_println!("[+] TA generate secret key: {}", secret_key);

    let public_key: u64 = power_mod(base, secret_key, p);
    trace_println!("[+] TA generate public key: {}", public_key);
    par.buffer()
        .copy_from_slice(u64::to_ne_bytes(public_key).as_ref());

    let shared_key: u64 = power_mod(incoming_public_key, secret_key, p);

    // Store keys in secure db within TEE
    let db_client = SecureStorageClient::open("secure_db")?;
    let public_key_db_entry = DbDataType {
        id: "public_key".to_string(),
        data: public_key,
    };
    db_client.put(&public_key_db_entry)?;
    let secret_key_db_entry = DbDataType {
        id: "secret_key".to_string(),
        data: secret_key,
    };
    db_client.put(&secret_key_db_entry)?;
    let shared_key_db_entry = DbDataType {
        id: "shared_key".to_string(),
        data: shared_key,
    };
    db_client.put(&shared_key_db_entry)?;
    let hash = DbDataType {
        id: "hash".to_string(),
        data: shared_key,
    }

    trace_println!("[+] TA computed shared key: {}", shared_key);
    db_client.put(&DbDataType {
        id: "shared_key".to_string(),
        data: shared_key,
    })?;

    let loaded_shared_key: DbDataType = db_client.get::<DbDataType>(&"shared_key".to_string())?;
    trace_println!(
        "[+] TA loaded shared key from secure db: {:?}",
        loaded_shared_key
    );

    Ok(())
}

fn power_mod(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result: u64 = 1;
    let mut base = base % modulus;
    let mut exp = exp;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    return result;
}

#[ta_invoke_command]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::IncomingKey => match incoming_key_compute(params) {
            Ok(_) => Ok(()),
            Err(e) => {
                trace_println!("[-] Symmetric key computation failed: {}", e);
                Err(Error::new(ErrorKind::Generic))
            }
        },
        _ => {
            trace_println!("[-] Command not found");
            Err(Error::new(ErrorKind::BadParameters))
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
