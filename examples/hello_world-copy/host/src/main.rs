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


#![allow(unused_imports)] // Imports behave a bit weird sometimes with Teaclave

use optee_teec::{Context, Operation, ParamNone, ParamTmpRef, Session, Uuid};
use proto::{Command, UUID};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn incoming_key_compute(session: &mut Session, incoming_buf: [u8; 8]) -> optee_teec::Result<u64> {
    let mut computed_buf = [0u8; 8];

    let p0 = ParamTmpRef::new_input(&incoming_buf);
    let p1 = ParamTmpRef::new_output(&mut computed_buf);
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);

    println!("Invoking TA to compute incoming key...");
    session.invoke_command(Command::IncomingKey as u32, &mut operation)?;

    let computed_key: u64 = u64::from_ne_bytes(incoming_buf);

    println!("TA-computed key from incoming key {}", computed_key);
    Ok(computed_key)
}

fn handle_client(ta_session: &mut Session, _session_id: u32, mut stream: TcpStream) -> Option<u64> {
    let mut public_key: u64 = 0;
    println!("new session");
    loop {
        let mut buf = [0u8; 8];
        println!("stream read");
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => {
                println!("close session");
                break;
            }
            Ok(n) => {
                println!("read bytes: {}", n);
                public_key = incoming_key_compute(ta_session, buf).unwrap();
                println!("Public key generated: {}", public_key);
            }
        }
    }

    Some(public_key)
}

fn main() {
    let mut ctx = Context::new().expect("Failed to create TEE context");
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid).expect("Failed to open TEE session");
    let mut session_id: u32 = 0;

    let listener = TcpListener::bind("127.0.0.1:9090").unwrap();
    println!("Listening on port 4433");
    for stream in listener.incoming() {
        session_id += 1;
        handle_client(&mut session, session_id, stream.unwrap()).expect("Failed to read buffer");
    }
}
