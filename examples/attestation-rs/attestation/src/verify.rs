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

//! Verification trait and related functionality

use crate::common::{
    AttestationKeyEndorsement, AttestationPubkey, AttestationReport, PlatformPubkey,
    PlatformPubkeyHash, Quote,
};
use anyhow::{ensure, Result};

/// Trait for verifying attestation reports
pub trait ReportVerification {
    fn verify_report(
        &self,
        attestation_pubkey: &AttestationPubkey,
        report: &AttestationReport,
    ) -> Result<()>;
}

/// Trait for verifying endorsements
pub trait EndorsementVerification {
    fn verify_endorsement(
        &self,
        platform_pubkey: &PlatformPubkey,
        endorsement: &AttestationKeyEndorsement,
    ) -> Result<()>;
}

/// Trait for components that can verify attestation quotes
///
/// This trait abstracts over the verification functionality for attestation quotes.
pub trait QuoteVerify {
    /// Verify an attestation quote
    ///
    /// # Arguments
    ///
    /// * `quote` - The attestation quote to verify
    ///
    /// # Returns
    ///
    /// Ok(()) if the quote is valid, Err otherwise
    fn verify_quote(&self, quote: &Quote) -> Result<()>;
}

/// Quote verifier that uses separate verifiers for reports and endorsements
pub struct QuoteVerifier<R: ReportVerification, E: EndorsementVerification> {
    report_verifier: R,
    endorsement_verifier: E,
    platform_pubkey: PlatformPubkey,
}

impl<R: ReportVerification, E: EndorsementVerification> QuoteVerifier<R, E> {
    pub fn new(
        report_verifier: R,
        endorsement_verifier: E,
        platform_pubkey: PlatformPubkey,
    ) -> Self {
        Self {
            report_verifier,
            endorsement_verifier,
            platform_pubkey,
        }
    }
}

impl<R: ReportVerification, E: EndorsementVerification> QuoteVerify for QuoteVerifier<R, E> {
    fn verify_quote(&self, quote: &Quote) -> Result<()> {
        let endorsement = &quote.attestation_key_endorsement;
        let report = &quote.report;

        // Verify platform key hash
        ensure!(
            endorsement.platform_pubkey_hash()
                == &PlatformPubkeyHash::from_pubkey(&self.platform_pubkey)?,
            "Platform public key hash mismatch"
        );

        // Verify endorsement
        self.endorsement_verifier
            .verify_endorsement(&self.platform_pubkey, endorsement)?;

        // Verify report
        self.report_verifier
            .verify_report(endorsement.attestation_pubkey(), report)?;

        Ok(())
    }
}
