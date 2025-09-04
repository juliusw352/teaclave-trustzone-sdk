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

#![allow(unused_imports)]
#![allow(dead_code)]
use optee_teec::{Context, Operation, ParamNone, ParamTmpRef, Session, Uuid};
use proto::{Command, UUID};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

/*
fn random(session: &mut Session) -> optee_teec::Result<u64> {
    let mut random_buf = [0u8; 8];

    let p0 = ParamTmpRef::new_output(&mut random_buf);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    println!("Invoking TA to generate random UUID...");
    session.invoke_command(Command::RandomGenerator as u32, &mut operation)?;
    println!("Invoking done!");

    let public_key: u64 = u64::from_ne_bytes(random_buf);

    println!("TA-generated public key: {}", public_key);
    Ok(public_key)
}
*/

fn incoming_key_compute(session: &mut Session, incoming_num: u64) -> optee_teec::Result<([0u8; 8])> {
    let incoming_buf = incoming_num.to_ne_bytes();
    let mut computed_buf = [0u8; 8];

    let p0 = ParamTmpRef::new_input(&incoming_buf);
    let p1 = ParamTmpRef::new_output(&mut computed_buf);
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);

    println!("Invoking TA to compute incoming key...");
    session.invoke_command(Command::IncomingKey as u32, &mut operation)?;
    println!("Invoking done!");

    let computed_key: u64 = u64::from_ne_bytes(computed_buf);

    println!(
        "TA-computed key from incoming key {}: {}",
        incoming_num, computed_key
    );
    Ok(computed_buf)
}

fn handle_client(_ta_session: &mut Session, _session_id: u32, mut stream: TcpStream) -> Option<()> {
    let mut buffer = [0; 8];

    loop {
        match stream.read(&mut buffer) {
            Ok(n) => {
                if n == 0 {
                    println!("Connection closed");
                }
                let incoming_num = u64::from_ne_bytes(buffer);
                println!("Received incoming number: {}", incoming_num);
                let response = incoming_key_compute(_ta_session, incoming_num)
                    .expect("Failed to store incoming key or generate own key pair");
                stream
                    .write_all(&response)
                    .expect("Failed to send response");
                println!("Response sent: {:?}", u64::from_ne_bytes(response));
                return Some(());
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                match e.kind() {
                    ErrorKind::ConnectionReset => {
                        println!("Client connection reset")
                    }
                    _ => {
                        eprintln!("Unexpected error: {}", e);
                    }
                };
            }
        };
        return None;
    }
}

/*fn handle_client(mut stream: TcpStream) -> Option<[u8; 8]> {
    let mut buffer = [0; 8];

    loop {
        match stream.read(&mut buffer) {
            Ok(n) => {
                if n == 0 {
                    println!("Connection closed");
                }
                return Some(buffer);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                match e.kind() {
                    ErrorKind::ConnectionReset => {
                        println!("Client connection reset")
                    }
                    _ => {
                        eprintln!("Unexpected error: {}", e);
                    }
                };
            }
        };
        return None;
    }
}

fn main() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;

    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    random(&mut session)?;
    let test_num: u64 = 12345;
    incoming_key_compute(&mut session, test_num)?;

    println!("Success");
    Ok(())
}

fn main() {
    let mut ctx = Context::new().expect("Failed to create TEE context");
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid).expect("Failed to open TEE session");

    let mut stream = TcpStream::connect("127.0.0.1:9090").expect("Failed to connect");

    let public_key = random(&mut session).expect("Failed to generate random key");

    println!("Sending public key to server: {}", public_key);
    stream
        .write_all(&public_key.to_ne_bytes())
        .expect("Failed to send public key");
    println!("Public key sent");
}
*/

fn main() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut ta_session = ctx.open_session(uuid)?;

    let mut session_id: u32 = 0;
    println!("listening");
    let listener = TcpListener::bind("127.0.0.1:4433").unwrap();

    for stream in listener.incoming() {
        session_id += 1;
        handle_client(&mut ta_session, session_id, stream.unwrap()).expect("Failed to read buffer");
    }

    println!("Success");
    Ok(())
}
