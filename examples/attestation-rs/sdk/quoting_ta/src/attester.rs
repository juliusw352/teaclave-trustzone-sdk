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

use anyhow::Result;
use attestation::{
    AttestationKeyManagement, AttestationPubkey, AttestationSignature, Identity, ReportBody,
    TaMeasurement,
};
use optee_utee::{trace_println, ParamIndex, TaSessionBuilder, TeeParams, Uuid};
use ring::signature::KeyPair;
use secure_db::{SecureStorageClient, Storable};
use serde::{Deserialize, Serialize};

use crate::pta_command::{AttestationPtaCommand, ATTESTATION_PTA_UUID, MAX_OUTPUT_SIZE};

/// Implementation of TaMeasurement that gets measurements from PTA
/// PTA is modified from OP-TEE original implementation
/// Please refer to the OP-TEE OS patch in "os" for more details
pub struct PtaAttester;

impl TaMeasurement for PtaAttester {
    fn measure_ta(&self, target_ta: &Identity) -> Result<ReportBody> {
        let input = target_ta.as_uuid();
        trace_println!("[+] Measuring TA: {:?}", input);
        let mut output = vec![0u8; MAX_OUTPUT_SIZE];

        let uuid = Uuid::parse_str(ATTESTATION_PTA_UUID)
            .map_err(|e| anyhow::anyhow!("Failed to parse UUID: {:?}", e))?;
        let mut session = TaSessionBuilder::new(uuid)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;

        let mut params = TeeParams::new()
            .with_memref_in(ParamIndex::Arg0, &input)
            .with_memref_out(ParamIndex::Arg1, &mut output);

        session
            .invoke_command(AttestationPtaCommand::GetReport as u32, &mut params)
            .map_err(|e| anyhow::anyhow!("Failed to invoke command: {:?}", e))?;

        // Get the output buffer through written_slice()
        let output = params[ParamIndex::Arg1]
            .written_slice()
            .ok_or(anyhow::anyhow!("Failed to get written slice"))?;

        // Deserialize the output into ReportBody
        let report_body = ReportBody::decode_from_bytes(output)?;
        trace_println!("[+] attestation report body: {:?}", report_body);

        Ok(report_body)
    }
}

const AK_DB_NAME: &str = "ak_db";
// Since we only have one ak pair, we can use a fixed key and overwrite the entry
const AK_STORAGE_KEY: &str = "ak";

// for storing the attestation key as a PKCS8 blob
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AttestationKeyBytes {
    pkcs8_bytes: Vec<u8>,
}

impl Storable for AttestationKeyBytes {
    type Key = String;

    fn unique_id(&self) -> Self::Key {
        // fix key
        AK_STORAGE_KEY.to_string()
    }
}

/// Implementation of AttestationKeyManagement that uses ECDSA for attestation key operations
pub struct EcdsaAttestationKeyManager {
    key_pair: ring::signature::EcdsaKeyPair,
}

impl EcdsaAttestationKeyManager {
    pub fn init() -> Result<Self> {
        trace_println!("[+] Initializing EcdsaAttestationKeyManager");

        let db_client = SecureStorageClient::open(AK_DB_NAME)
            .map_err(|e| anyhow::anyhow!("Failed to open secure storage: {:?}", e))?;
        trace_println!("[+] Opened secure storage");

        // check if the key pair exists in the db, if not, generate a new one
        match db_client.get::<AttestationKeyBytes>(&AK_STORAGE_KEY.to_string()) {
            Ok(ak) => {
                trace_println!("[+] Found existing ECDSA key pair in secure storage");
                let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                    &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    ak.pkcs8_bytes.as_ref(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to create ECDSA key pair: {:?}", e))?;
                Ok(Self { key_pair })
            }
            Err(e) => {
                trace_println!(
                    "[-] Failed to get ECDSA key pair from secure storage: {:?}",
                    e
                );
                let rng = ring::rand::SystemRandom::new();
                let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
                    &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &rng,
                )
                .map_err(|e| anyhow::anyhow!("Failed to generate ECDSA key pair: {:?}", e))?;
                trace_println!("[+] Generated new ECDSA pkcs8 bytes");
                let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                    &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    pkcs8_bytes.as_ref(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to create ECDSA key pair: {:?}", e))?;
                trace_println!("[+] Generated new ECDSA key pair");

                let ak = AttestationKeyBytes {
                    pkcs8_bytes: pkcs8_bytes.as_ref().to_vec(),
                };
                db_client.put(&ak)?;
                Ok(Self { key_pair })
            }
        }
    }
}

impl AttestationKeyManagement for EcdsaAttestationKeyManager {
    fn sign(&self, data: &[u8]) -> Result<AttestationSignature> {
        let rng = ring::rand::SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&rng, data)
            .map_err(|_| anyhow::anyhow!("Failed to sign data"))?;

        Ok(AttestationSignature::from_bytes(signature.as_ref()))
    }

    fn get_attestation_pubkey(&self) -> Result<AttestationPubkey> {
        Ok(AttestationPubkey::from_bytes(
            self.key_pair.public_key().as_ref(),
        ))
    }
}
