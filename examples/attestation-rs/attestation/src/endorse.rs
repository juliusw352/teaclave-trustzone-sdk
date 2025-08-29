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

//! Endorsement trait and related functionality

use crate::common::{
    AttestationKeyEndorsement, AttestationPubkey, AttestationReport, EndorsementBody,
    EndorsementSignature, PlatformPubkey, PlatformPubkeyHash,
};
use crate::verify::ReportVerification;
use anyhow::{Context, Result};

/// Trait for components that can endorse attestation keys
///
/// This trait abstracts over the manufacturing protection (MP) functionality
/// provided by a MP PTA (Pseudo Trusted Application) in OpTEE.
pub trait Endorsing {
    /// Endorse an attestation key with the platform key
    ///
    /// # Arguments
    ///
    /// * `attestation_pubkey` - The attestation public key to endorse
    /// * `quoter_report` - The TA report for the QuoteTA
    ///
    /// # Returns
    ///
    /// An endorsement with signature of the platform key
    fn endorse_attestation_pubkey(
        &self,
        attestation_pubkey: AttestationPubkey,
        quoter_report: AttestationReport,
    ) -> Result<AttestationKeyEndorsement>;
}

pub trait PlatformKeyManagement {
    /// Sign the given data with the endorsing key
    fn sign(&self, data: &[u8]) -> Result<EndorsementSignature>;

    /// Get the public endorsing key
    fn get_platform_pubkey(&self) -> Result<PlatformPubkey>;

    /// tick the endorsement counter to track the number of times the platform key has been used
    fn tick_counter(&self) -> Result<u32>;
}

pub struct Endorser<K: PlatformKeyManagement, V: ReportVerification> {
    platform_key_manager: K,
    quote_verifier: V,
}

impl<K: PlatformKeyManagement, V: ReportVerification> Endorser<K, V> {
    pub fn new(platform_key_manager: K, quote_verifier: V) -> Self {
        Self {
            platform_key_manager,
            quote_verifier,
        }
    }
}

impl<K: PlatformKeyManagement, V: ReportVerification> Endorsing for Endorser<K, V> {
    fn endorse_attestation_pubkey(
        &self,
        attestation_pubkey: AttestationPubkey,
        quoter_report: AttestationReport,
    ) -> Result<AttestationKeyEndorsement> {
        self.quote_verifier
            .verify_report(&attestation_pubkey, &quoter_report)
            .context("Failed to verify quoter report")?;

        let platform_pubkey = self.platform_key_manager.get_platform_pubkey()?;
        let counter = self.platform_key_manager.tick_counter()?;

        let platform_pubkey_hash = PlatformPubkeyHash::from_pubkey(&platform_pubkey)?;
        let body = EndorsementBody::new(
            attestation_pubkey,
            platform_pubkey_hash,
            counter,
            quoter_report,
        );

        let hash = body.signing_hash();
        let signature = self.platform_key_manager.sign(&hash)?;

        let endorsement = AttestationKeyEndorsement::new(body, signature);
        Ok(endorsement)
    }
}
