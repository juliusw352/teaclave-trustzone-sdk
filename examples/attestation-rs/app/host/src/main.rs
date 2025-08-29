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

mod cli;
mod measurements;
mod verifier;

use crate::measurements::MeasurementsRecorded;
use crate::verifier::{EcdsaEndorsementVerifier, EcdsaReportVerifier};
use attestation::{PlatformPubkey, Quote, QuoteVerifier, QuoteVerify, UserData};
use clap::Parser;
use optee_teec::{Context, Operation, ParamNone, ParamTmpRef, Uuid};
use proto::{Command, MAX_OUTPUT_SIZE, UUID};
use std::io::Write;

fn main() -> optee_teec::Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Command::GetQuote { user_data, output } => {
            let quote = get_quote(user_data)?;
            println!("NW: Quote: {:?}", quote);
            write_quote_to_file(&quote, &output).map_err(|e| {
                println!("NW: Write quote to file failed: {:?}", e);
                optee_teec::Error::new(optee_teec::ErrorKind::BadParameters)
            })?;
            println!("NW: Quote written to file: {:?}", output);
            Ok(())
        }
        cli::Command::VerifyQuote {
            quote,
            user_data,
            endorse_pubkey,
            measurements,
        } => verify_quote(*quote, user_data, endorse_pubkey, *measurements).map_err(|e| {
            println!("NW: Verify quote failed: {:?}", e);
            optee_teec::Error::new(optee_teec::ErrorKind::BadParameters)
        }),
    }
}

fn get_quote(user_data: UserData) -> optee_teec::Result<Quote> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).map_err(|e| {
        println!("NW: Parse UUID failed: {:?}", e);
        optee_teec::Error::new(optee_teec::ErrorKind::BadParameters)
    })?;
    let mut session = ctx.open_session(uuid)?;

    let p0 = ParamTmpRef::new_input(user_data.as_bytes());
    let mut output_quote = [0u8; MAX_OUTPUT_SIZE];
    let p1 = ParamTmpRef::new_output(&mut output_quote);

    let mut op = Operation::new(0, p0, p1, ParamNone, ParamNone);
    session.invoke_command(Command::GetQuote as u32, &mut op)?;

    let quote: Quote = bincode::deserialize(&output_quote).map_err(|e| {
        println!("NW: Deserialize quote failed: {:?}", e);
        optee_teec::Error::new(optee_teec::ErrorKind::BadParameters)
    })?;
    Ok(quote)
}

fn write_quote_to_file(quote: &Quote, path: &std::path::Path) -> anyhow::Result<()> {
    let serialized_quote = serde_json::to_string(quote)?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(serialized_quote.as_bytes())?;
    Ok(())
}

fn verify_quote(
    quote: Quote,
    user_data: UserData,
    platform_pk: PlatformPubkey,
    measurements: MeasurementsRecorded,
) -> anyhow::Result<()> {
    // check: signature, user_data, measurements
    let report_verifier = EcdsaReportVerifier {
        user_data,
        measurements,
    };

    // check: signature
    let endorsement_verifier = EcdsaEndorsementVerifier;

    // Create quote verifier
    let verifier = QuoteVerifier::new(report_verifier, endorsement_verifier, platform_pk);

    // Verify the quote
    verifier.verify_quote(&quote)?;
    Ok(())
}
