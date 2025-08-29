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

//! Common types and structures for attestation

use anyhow::{ensure, Result};
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::fmt;

/// Platform public key hash (SHA-256)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformPubkeyHash([u8; 32]);

impl PlatformPubkeyHash {
    pub fn from_pubkey(pubkey: &PlatformPubkey) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(pubkey.as_bytes());
        let hash = hasher.finalize();
        let hash_bytes: [u8; 32] = hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert hash to array"))?;
        Ok(Self(hash_bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for PlatformPubkeyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

/// Platform public key (RSA 3072)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformPubkey(Vec<u8>);

impl PlatformPubkey {
    /// Create a new PlatformPubkey from raw bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        PlatformPubkey(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert into raw bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() > 4,
            "Platform public key must be more than 4 bytes"
        );
        Ok(Self(bytes.to_vec()))
    }
}

impl fmt::Display for PlatformPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

/// Attestation public key (supports various algorithms)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationPubkey(Vec<u8>);

impl AttestationPubkey {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.0);
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }
}

impl fmt::Display for AttestationPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

/// Attestation signature (supports various algorithms)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationSignature(Vec<u8>);

impl AttestationSignature {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for AttestationSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

/// Endorsement signature (RSA 3072)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndorsementSignature(Vec<u8>); // RSA 3072 signature is 384 bytes

impl EndorsementSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for EndorsementSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

/// Identity of a Trusted Application (UUID)
#[derive(Debug, Clone)]
pub struct Identity {
    /// TA UUID
    uuid: [u8; 16],
}

impl Identity {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self { uuid }
    }

    pub fn as_uuid(&self) -> [u8; 16] {
        self.uuid
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.uuid[0], self.uuid[1], self.uuid[2], self.uuid[3],
            self.uuid[4], self.uuid[5],
            self.uuid[6], self.uuid[7],
            self.uuid[8], self.uuid[9],
            self.uuid[10], self.uuid[11], self.uuid[12], self.uuid[13], self.uuid[14], self.uuid[15]
        )
    }
}

impl TryFrom<String> for Identity {
    type Error = anyhow::Error;
    // format: "{:08x}-{:04x}-{:04x}-{}-{}"
    fn try_from(value: String) -> Result<Self> {
        let mut uuid = [0u8; 16];
        let parts: Vec<&str> = value.split('-').collect();
        ensure!(parts.len() == 5, "Invalid UUID format");

        // Using big-endian order, follow the spec: https://www.ietf.org/rfc/rfc4122.txt
        uuid[0..4].copy_from_slice(&u32::from_str_radix(parts[0], 16)?.to_be_bytes());
        uuid[4..6].copy_from_slice(&u16::from_str_radix(parts[1], 16)?.to_be_bytes());
        uuid[6..8].copy_from_slice(&u16::from_str_radix(parts[2], 16)?.to_be_bytes());
        uuid[8..10].copy_from_slice(&hex::decode(parts[3])?);
        uuid[10..].copy_from_slice(&hex::decode(parts[4])?);

        Ok(Self { uuid })
    }
}

/// Attestation report for a TA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBody {
    /// TA UUID
    pub ta_id: [u8; 16],
    /// Measurement of TA binary
    pub mr_ta_binary: [u8; 32],
    /// Measurement of TA memory
    pub mr_ta_memory: [u8; 32],
    /// Measurement of OS memory
    pub mr_os_memory: [u8; 32],
}

impl ReportBody {
    pub fn signing_data(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.ta_id);
        vec.extend_from_slice(&self.mr_ta_binary);
        vec.extend_from_slice(&self.mr_ta_memory);
        vec.extend_from_slice(&self.mr_os_memory);
        vec
    }

    pub fn decode_from_bytes(bytes: &[u8]) -> Result<Self> {
        // ensure the length is size of report body
        ensure!(
            bytes.len() == core::mem::size_of::<ReportBody>(),
            "Wrong length of report body: {}",
            bytes.len()
        );
        let mut ta_id = [0u8; 16];
        let mut mr_ta_binary = [0u8; 32];
        let mut mr_ta_memory = [0u8; 32];
        let mut mr_os_memory = [0u8; 32];

        ta_id.copy_from_slice(&bytes[0..16]);
        mr_ta_binary.copy_from_slice(&bytes[16..48]);
        mr_ta_memory.copy_from_slice(&bytes[48..80]);
        mr_os_memory.copy_from_slice(&bytes[80..112]);

        Ok(Self {
            ta_id,
            mr_ta_binary,
            mr_ta_memory,
            mr_os_memory,
        })
    }
}

impl fmt::Display for ReportBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let indent = f.width().unwrap_or(0);
        writeln!(f, "{{")?;
        writeln!(
            f,
            "{:indent$}  ta_id: {},",
            "",
            hex::encode(self.ta_id),
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  mr_ta_binary: {},",
            "",
            hex::encode(self.mr_ta_binary),
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  mr_ta_memory: {},",
            "",
            hex::encode(self.mr_ta_memory),
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  mr_os_memory: {},",
            "",
            hex::encode(self.mr_os_memory),
            indent = indent
        )?;
        write!(f, "{:indent$}}}", "", indent = indent)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserData {
    data: [u8; 32],
}

impl UserData {
    pub fn new(data: [u8; 32]) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.data
    }

    pub fn from_fix_str(s: &str) -> Result<Self> {
        ensure!(s.len() <= 32, "fix_str must be less than 32 bytes");
        let mut data = [0u8; 32];
        data[..s.len()].copy_from_slice(s.as_bytes());
        Ok(Self { data })
    }
}

impl TryFrom<Vec<u8>> for UserData {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        ensure!(value.len() <= 32, "User data must be less than 32 bytes");
        let mut data = [0u8; 32];
        data[..value.len()].copy_from_slice(&value);
        Ok(Self { data })
    }
}

impl fmt::Display for UserData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Report body
    body: ReportBody,
    /// User data
    user_data: UserData,
    /// Signature over the report body
    signature: AttestationSignature,
}

impl fmt::Display for AttestationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let indent = f.width().unwrap_or(0);
        writeln!(f, "{{")?;
        writeln!(
            f,
            "{:indent$}  body: {},",
            "",
            format!("{:width$}", self.body, width = indent + 2),
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  user_data: {},",
            "",
            self.user_data,
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  signature: {},",
            "",
            self.signature,
            indent = indent
        )?;
        write!(f, "{:indent$}}}", "", indent = indent)
    }
}

impl AttestationReport {
    pub fn new(body: ReportBody, user_data: UserData, signature: AttestationSignature) -> Self {
        Self {
            body,
            user_data,
            signature,
        }
    }

    pub fn signing_data(&self) -> Vec<u8> {
        let mut vec = self.body.signing_data();
        vec.extend_from_slice(self.user_data.as_bytes());
        vec
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = self.signing_data();
        vec.extend_from_slice(self.signature.as_bytes());
        vec
    }

    pub fn signature(&self) -> &AttestationSignature {
        &self.signature
    }

    pub fn report_body(&self) -> &ReportBody {
        &self.body
    }

    pub fn user_data(&self) -> &UserData {
        &self.user_data
    }
}

/// Attestation key endorsement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndorsementBody {
    /// Attestation key public key
    attestation_pubkey: AttestationPubkey,
    /// Platform public key
    platform_pubkey_hash: PlatformPubkeyHash,
    /// Endorsement counter
    counter: u32,
    /// Quoter report
    quoter_report: AttestationReport,
}

impl fmt::Display for EndorsementBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let indent = f.width().unwrap_or(0);
        writeln!(f, "{{")?;
        writeln!(
            f,
            "{:indent$}  attestation_pubkey: {},",
            "",
            self.attestation_pubkey,
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  platform_pubkey_hash: {},",
            "",
            self.platform_pubkey_hash,
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  counter: {},",
            "",
            self.counter,
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  quoter_report: {},",
            "",
            format!("{:width$}", self.quoter_report, width = indent + 2),
            indent = indent
        )?;
        write!(f, "{:indent$}}}", "", indent = indent)
    }
}

impl EndorsementBody {
    pub fn new(
        attestation_pubkey: AttestationPubkey,
        platform_pubkey_hash: PlatformPubkeyHash,
        counter: u32,
        quoter_report: AttestationReport,
    ) -> Self {
        Self {
            attestation_pubkey,
            platform_pubkey_hash,
            counter,
            quoter_report,
        }
    }

    pub fn attestation_pubkey(&self) -> &AttestationPubkey {
        &self.attestation_pubkey
    }

    pub fn platform_pubkey_hash(&self) -> &PlatformPubkeyHash {
        &self.platform_pubkey_hash
    }

    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn quoter_report(&self) -> &AttestationReport {
        &self.quoter_report
    }
}

/// Attestation key endorsement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationKeyEndorsement {
    body: EndorsementBody,
    /// Endorsement signature
    signature: EndorsementSignature,
}

impl fmt::Display for AttestationKeyEndorsement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let indent = f.width().unwrap_or(0);
        writeln!(f, "{{")?;
        writeln!(
            f,
            "{:indent$}  body: {},",
            "",
            format!("{:width$}", self.body, width = indent + 2),
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  signature: {},",
            "",
            self.signature,
            indent = indent
        )?;
        write!(f, "{:indent$}}}", "", indent = indent)
    }
}

impl AttestationKeyEndorsement {
    pub fn new(body: EndorsementBody, signature: EndorsementSignature) -> Self {
        Self { body, signature }
    }

    pub fn platform_pubkey_hash(&self) -> &PlatformPubkeyHash {
        self.body.platform_pubkey_hash()
    }

    pub fn attestation_pubkey(&self) -> &AttestationPubkey {
        self.body.attestation_pubkey()
    }

    pub fn counter(&self) -> u32 {
        self.body.counter
    }

    pub fn quoter_report(&self) -> &AttestationReport {
        self.body.quoter_report()
    }

    pub fn signature(&self) -> &EndorsementSignature {
        &self.signature
    }

    pub fn signing_hash(&self) -> Vec<u8> {
        self.body.signing_hash()
    }
}

impl EndorsementBody {
    pub fn signing_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.attestation_pubkey.as_bytes());
        hasher.update(self.platform_pubkey_hash.as_bytes());
        hasher.update(self.counter.to_be_bytes());
        let body = self.quoter_report.to_vec();
        hasher.update(&body);
        hasher.finalize().to_vec()
    }
}

/// Attestation quote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    /// Attestation report for the target TA
    pub report: AttestationReport,
    /// Attestation key endorsement
    pub attestation_key_endorsement: AttestationKeyEndorsement,
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let indent = f.width().unwrap_or(0);
        writeln!(f, "{{")?;
        writeln!(
            f,
            "{:indent$}  report: {},",
            "",
            format!("{:width$}", self.report, width = indent + 2),
            indent = indent
        )?;
        writeln!(
            f,
            "{:indent$}  attestation_key_endorsement: {},",
            "",
            format!(
                "{:width$}",
                self.attestation_key_endorsement,
                width = indent + 2
            ),
            indent = indent
        )?;
        write!(f, "{:indent$}}}", "", indent = indent)
    }
}
