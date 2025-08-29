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

mod attest;
mod common;
mod endorse;
mod verify;

pub use attest::{AttestationKeyManagement, Attester, Attesting, TaMeasurement};
pub use common::*;
pub use endorse::{Endorser, Endorsing, PlatformKeyManagement};
pub use verify::{EndorsementVerification, QuoteVerifier, QuoteVerify, ReportVerification};

pub trait EndorsementStore {
    /// Get an existing endorsement for the given attestation key
    fn get_endorsement(
        &self,
        attestation_pubkey: &AttestationPubkey,
    ) -> Option<AttestationKeyEndorsement>;

    /// Store the endorsement
    fn store_endorsement(&self, endorsement: AttestationKeyEndorsement) -> Result<()>;
}

pub struct Quoter<A: Attesting, E: Endorsing, S: EndorsementStore> {
    identity: Identity,
    attester: A,
    endorser: E,
    endorsement_store: S,
}

impl<A: Attesting, E: Endorsing, S: EndorsementStore> Quoter<A, E, S> {
    pub fn new(identity: Identity, attester: A, endorser: E, endorsement_store: S) -> Self {
        Self {
            identity,
            attester,
            endorser,
            endorsement_store,
        }
    }

    fn endorsing_attestation_pubkey(
        &self,
        attestation_pubkey: AttestationPubkey,
    ) -> Result<AttestationKeyEndorsement> {
        let user_data = UserData::from_fix_str("QUOTER_SELF_ATTEST")?;
        let quoter_report = self.attester.attest_ta(&self.identity, user_data)?;
        self.endorser
            .endorse_attestation_pubkey(attestation_pubkey, quoter_report)
    }

    pub fn get_quote(&self, target_ta: &Identity, user_data: UserData) -> Result<Quote> {
        // First get the attestation key and endorsement (attest the quoter)
        let attestation_pubkey = self.attester.get_attestation_pubkey()?;

        let attestation_key_endorsement =
            match self.endorsement_store.get_endorsement(&attestation_pubkey) {
                Some(attestation_key_endorsement) => attestation_key_endorsement,
                None => self.endorsing_attestation_pubkey(attestation_pubkey)?,
            };

        // Then get the attest the target TA
        let ta_report = self.attester.attest_ta(target_ta, user_data)?;

        // Return the complete quote
        Ok(Quote {
            report: ta_report,
            attestation_key_endorsement,
        })
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    pub mod attestation_flow;
}
