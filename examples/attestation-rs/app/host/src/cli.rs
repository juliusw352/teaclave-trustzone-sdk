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

use crate::measurements::MeasurementsRecorded;
use anyhow::{anyhow, Context, Result};
use attestation::{PlatformPubkey, Quote, UserData};
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};

/// Parse a hex string into Vec<u8>
fn parse_user_data(hex: &str) -> Result<UserData> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);

    if hex.len() % 2 != 0 || hex.len() > 64 {
        return Err(anyhow!(
            "Nonce hex string must have even length and be at most 32 bytes"
        ));
    }
    let mut data = [0u8; 32];
    // hex decode
    let decoded = hex::decode(hex).context("Failed to decode hex string")?;
    data[..decoded.len()].copy_from_slice(&decoded);
    Ok(UserData::new(data))
}

/// Parse a quote from a JSON file
fn parse_quote(path: &str) -> Result<Box<Quote>> {
    let data = fs::read(path).with_context(|| format!("Failed to read quote from {}", path))?;
    let quote = serde_json::from_slice(&data)
        .with_context(|| format!("Failed to parse quote from {}", path))?;
    Ok(Box::new(quote))
}

/// Parse measurements from a JSON file
fn parse_measurements(path: &str) -> Result<Box<MeasurementsRecorded>> {
    let data =
        fs::read(path).with_context(|| format!("Failed to read measurements from {}", path))?;
    let json = String::from_utf8_lossy(&data);
    let measurements = serde_json::from_str(&json)
        .map_err(|e| anyhow!("Failed to parse measurements from {}: {}", path, e))?;
    Ok(Box::new(measurements))
}

/// Parse a public key from hex string
fn parse_pk(path: &str) -> Result<PlatformPubkey> {
    let data =
        fs::read(path).with_context(|| format!("Failed to read public key from {}", path))?;
    let hex = String::from_utf8_lossy(&data);
    // Remove "0x" prefix if present
    let hex = hex.strip_prefix("0x").unwrap_or(&hex);
    let decoded = hex::decode(hex).context("Failed to decode hex string")?;

    PlatformPubkey::from_bytes(&decoded)
}

#[derive(Parser)]
#[command(
    name = "attestation-cli",
    version,
    about = "Attestation CLI Tool for quote generation and verification",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Get an attestation quote for the current TA
    GetQuote {
        /// User data in hex format (max 32 bytes)
        #[arg(short, long, value_parser = parse_user_data)]
        user_data: UserData,

        /// Output path for the quote JSON file
        #[arg(short, long, default_value = "quote.json")]
        output: PathBuf,
    },

    /// Verify an attestation quote
    VerifyQuote {
        /// Path to the quote JSON file
        /// We use Box<Quote> to reduce the total size of enum,
        /// which is enforced by clippy: #[warn(clippy::large_enum_variant)]
        #[arg(short, long, value_parser = parse_quote)]
        quote: Box<Quote>,

        /// Expected user data in hex format
        #[arg(short, long, value_parser = parse_user_data)]
        user_data: UserData,

        /// Path to the endorsement public key file
        #[arg(short, long, value_parser = parse_pk)]
        endorse_pubkey: PlatformPubkey,

        /// Path to the expected measurements JSON file
        #[arg(short, long, value_parser = parse_measurements)]
        measurements: Box<MeasurementsRecorded>,
    },
}
