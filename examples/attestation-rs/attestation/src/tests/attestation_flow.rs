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

//! Integration tests for the optee-attestation crate

use crate::{
    AttestationKeyEndorsement, AttestationKeyManagement, AttestationPubkey, AttestationSignature,
    Attester, EndorsementSignature, EndorsementStore, EndorsementVerification, Endorser, Identity,
    PlatformKeyManagement, PlatformPubkey, QuoteVerifier, QuoteVerify, Quoter, ReportBody,
    ReportVerification, UserData,
};
use anyhow::Result;

use std::collections::HashMap;
use std::sync::Mutex;

use ring::{
    rand,
    signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    },
};

/// Algorithm Selection in Demonstration:
/// 1. Design Flexibility:
///    Our attestation system is algorithm-agnostic. Developers can implement any signing algorithm
///    by implementing the required traits, allowing for different security and performance tradeoffs.
///
/// 2. We choose ECDSA for demonstration, the common choices are:
///    - ECDSA_P256_SHA256_FIXED: Fixed-length signatures, optimized for IoT/embedded systems
///    - ECDSA_P256_SHA256_ASN1_SIGNING: DER-encoded signatures, variable length, widely used in PKI/TLS
///
/// 3. Test Implementation Choice:
///    We choose ECDSA_P256_SHA256_ASN1_SIGNING for this test because:
///    - Compatible with common PKI tools and libraries (OpenSSL, Rustls, Webpki)
///    - Easy to integrate with higher-level security protocols

/// structs for Attester: This defines how does the attestation key managed
struct MockAttestationKeyManager {
    private_key: EcdsaKeyPair,
}

impl MockAttestationKeyManager {
    fn new() -> Result<Self> {
        // Generate a new key pair
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate attestation key: {:?}", e))?;

        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to generate attestation key: {:?}", e))?;
        Ok(Self {
            private_key: key_pair,
        })
    }
}

impl AttestationKeyManagement for MockAttestationKeyManager {
    fn sign(&self, data: &[u8]) -> Result<AttestationSignature> {
        let rng = rand::SystemRandom::new();
        let signature = self
            .private_key
            .sign(&rng, data)
            .map_err(|e| anyhow::anyhow!("Failed to sign attestation: {:?}", e))?;

        Ok(AttestationSignature::from_bytes(signature.as_ref()))
    }

    fn get_attestation_pubkey(&self) -> Result<AttestationPubkey> {
        Ok(AttestationPubkey::from_bytes(
            &self.private_key.public_key().as_ref(),
        ))
    }
}

/// structs for Attester: This defines how to measure the TA
struct MockTaMeasurer;

impl crate::attest::TaMeasurement for MockTaMeasurer {
    fn measure_ta(&self, target_ta: &Identity) -> Result<crate::common::ReportBody> {
        Ok(ReportBody {
            ta_id: target_ta.as_uuid(),
            mr_ta_binary: [0xaa; 32],
            mr_ta_memory: [0xbb; 32],
            mr_os_memory: [0xcc; 32],
        })
    }
}

/// structs for Endorser: This defines how does the endorser manage the platform key
struct MockPlatformKeyManager {
    private_key: EcdsaKeyPair,
    counter: Mutex<u32>,
}

impl MockPlatformKeyManager {
    fn new() -> Result<Self> {
        // Generate a new key pair for platform
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate platform key: {:?}", e))?;

        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to generate platform key: {:?}", e))?;

        Ok(Self {
            private_key: key_pair,
            counter: Mutex::new(0),
        })
    }
}

impl PlatformKeyManagement for MockPlatformKeyManager {
    fn sign(&self, data: &[u8]) -> Result<EndorsementSignature> {
        let rng = rand::SystemRandom::new();
        let signature = self
            .private_key
            .sign(&rng, data)
            .map_err(|e| anyhow::anyhow!("Failed to sign endorsement: {:?}", e))?;
        EndorsementSignature::from_bytes(signature.as_ref())
    }

    fn get_platform_pubkey(&self) -> Result<PlatformPubkey> {
        Ok(PlatformPubkey::new(
            self.private_key.public_key().as_ref().to_vec(),
        ))
    }

    fn tick_counter(&self) -> Result<u32> {
        let mut counter = self.counter.lock().unwrap();
        *counter = counter.wrapping_add(1);
        Ok(*counter)
    }
}

/// structs for Endorser: This defines how does the endorser store the endorsements
struct MockEndorsementStore {
    endorsements: Mutex<HashMap<Vec<u8>, AttestationKeyEndorsement>>,
}

impl Default for MockEndorsementStore {
    fn default() -> Self {
        Self {
            endorsements: Mutex::new(HashMap::new()),
        }
    }
}

impl EndorsementStore for MockEndorsementStore {
    fn get_endorsement(
        &self,
        attestation_pubkey: &AttestationPubkey,
    ) -> Option<AttestationKeyEndorsement> {
        self.endorsements
            .lock()
            .unwrap()
            .get(attestation_pubkey.as_bytes())
            .cloned()
    }

    fn store_endorsement(&self, endorsement: AttestationKeyEndorsement) -> Result<()> {
        self.endorsements.lock().unwrap().insert(
            endorsement.attestation_pubkey().as_bytes().to_vec(),
            endorsement,
        );
        Ok(())
    }
}

/// structs for Endorser: This defines how does the endorser verify the quoter's report
struct MockQuoterReportVerifier;

impl ReportVerification for MockQuoterReportVerifier {
    fn verify_report(
        &self,
        attestation_pubkey: &AttestationPubkey,
        report: &crate::common::AttestationReport,
    ) -> Result<()> {
        let public_key =
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, attestation_pubkey.as_bytes());

        // verify the signature of the report
        let signature = report.signature().as_bytes();
        public_key
            .verify(&report.signing_data(), signature)
            .map_err(|e| anyhow::anyhow!("Failed to verify report signature: {:?}", e))
    }
}

/// structs for ClientVerifier: This defines how does the client verify the App TA report
struct MockReportVerifier;

impl ReportVerification for MockReportVerifier {
    fn verify_report(
        &self,
        attestation_pubkey: &AttestationPubkey,
        report: &crate::common::AttestationReport,
    ) -> Result<()> {
        let public_key =
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, attestation_pubkey.as_bytes());

        // verify the signature of the report
        let signature = report.signature().as_bytes();
        public_key
            .verify(&report.signing_data(), signature)
            .map_err(|e| anyhow::anyhow!("Failed to verify report signature: {:?}", e))
    }
}

/// structs for ClientVerifier: This defines how does the client verify the Attestation Key endorsement
struct MockEndorsementVerifier;

impl EndorsementVerification for MockEndorsementVerifier {
    fn verify_endorsement(
        &self,
        platform_pubkey: &PlatformPubkey,
        endorsement: &AttestationKeyEndorsement,
    ) -> Result<()> {
        let public_key =
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, platform_pubkey.as_bytes());

        // verify the signature of the endorsement
        let signature = endorsement.signature().as_bytes();
        public_key
            .verify(&endorsement.signing_hash(), signature)
            .map_err(|e| anyhow::anyhow!("Failed to verify endorsement signature: {:?}", e))
    }
}

#[test]
fn test_attestation_flow() -> Result<()> {
    // get quote:
    // Setup mock components
    let attestation_key_manager = MockAttestationKeyManager::new()?;
    let ta_measuring = MockTaMeasurer;
    let platform_key_manager = MockPlatformKeyManager::new()?;
    let endorsement_store = MockEndorsementStore::default();
    let quoter_report_verifier = MockQuoterReportVerifier;

    // Get the platform pubkey for verification
    let platform_pubkey = platform_key_manager.get_platform_pubkey()?;

    // Create attester and endorser
    let attester = Attester::new(attestation_key_manager, ta_measuring);
    let endorser = Endorser::new(platform_key_manager, quoter_report_verifier);

    // Create quoter with this TA's identity
    let quoter_identity = Identity::new([6; 16]);
    let quoter = Quoter::new(quoter_identity, attester, endorser, endorsement_store);

    // Test get_quote
    let target_ta = Identity::new([7; 16]);
    let user_data = UserData::new([8; 32]);
    let quote = quoter.get_quote(&target_ta, user_data)?;
    println!("quote: {}", quote);
    println!("--------------------------------");
    println!("report: {}", quote.report);
    println!("--------------------------------");
    println!("endorsement: {}", quote.attestation_key_endorsement);
    println!("--------------------------------");

    // verify quote:
    // Test verify_quote
    let report_verifier = MockReportVerifier;
    let endorsement_verifier = MockEndorsementVerifier;
    let verifier = QuoteVerifier::new(report_verifier, endorsement_verifier, platform_pubkey);
    verifier.verify_quote(&quote)?;

    Ok(())
}
