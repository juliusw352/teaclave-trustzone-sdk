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
use ring::rand;
use ring::signature;
use ring::signature::KeyPair;

use attestation::{
    AttestationPubkey, AttestationReport, EndorsementSignature, PlatformKeyManagement,
    PlatformPubkey, ReportVerification,
};
use optee_utee::trace_println;
use std::sync::atomic::{AtomicU32, Ordering};

/// ECDSA platform key stored as DER-encoded PKCS#8 format
/// For production use, this should be stored in secure hardware storage
const PLATFORM_KEY_DER: &[u8] = include_bytes!("../test_keys/platform_key.der");

/// Implementation of PlatformKeyManagement that uses ECDSA for platform key operations
pub struct EcdsaPlatformKeyManager {
    key_pair: signature::EcdsaKeyPair,
    counter: AtomicU32,
}

impl EcdsaPlatformKeyManager {
    pub fn init() -> Result<Self> {
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            PLATFORM_KEY_DER,
        )
        .map_err(|e| anyhow::anyhow!("Failed to load ECDSA key pair: {:?}", e))?;

        Ok(Self {
            key_pair,
            counter: AtomicU32::new(0),
        })
    }
}

impl PlatformKeyManagement for EcdsaPlatformKeyManager {
    fn sign(&self, data: &[u8]) -> Result<EndorsementSignature> {
        let rng = rand::SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&rng, data)
            .map_err(|_| anyhow::anyhow!("Failed to sign data"))?;

        trace_println!("[+] Platform key signing data");
        EndorsementSignature::from_bytes(signature.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to create endorsement signature: {:?}", e))
    }

    fn get_platform_pubkey(&self) -> Result<PlatformPubkey> {
        trace_println!("[+] Getting platform public key");
        PlatformPubkey::from_bytes(self.key_pair.public_key().as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to create platform public key: {:?}", e))
    }

    fn tick_counter(&self) -> Result<u32> {
        let new_value = self.counter.fetch_add(1, Ordering::SeqCst);
        trace_println!("[+] Platform key counter ticked to: {}", new_value);
        Ok(new_value)
    }
}

/// Implementation of ReportVerification for the quoting TA
/// This defines how does the endorser verify the quoter's report
pub struct QuotingTaReportVerifier;

impl ReportVerification for QuotingTaReportVerifier {
    fn verify_report(&self, att_pk: &AttestationPubkey, report: &AttestationReport) -> Result<()> {
        // Implement the verification logic specific to the quoting TA
        // This might involve checking signatures, measurements, etc.
        trace_println!("[+] Endorsement: verifying quoter's report");

        // Verify the report signature
        let signature = report.signature();
        let data = report.signing_data();
        let ak_pub = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            att_pk.as_bytes(),
        );
        ak_pub
            .verify(&data, signature.as_bytes())
            .map_err(|e| anyhow::anyhow!("[+] Endorsement: failed to verify report: {:?}", e))?;
        trace_println!("[+] Report verified successfully");
        Ok(())
    }
}
