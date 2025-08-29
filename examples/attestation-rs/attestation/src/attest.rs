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

//! Attestation trait and related functionality

use crate::common::{
    AttestationPubkey, AttestationReport, AttestationSignature, Identity, ReportBody, UserData,
};
use anyhow::Result;

/// Trait for components that can perform attestation
///
/// This trait abstracts over the attestation functionality provided by
/// an attestation PTA (Pseudo Trusted Application) in OpTEE.
pub trait Attesting {
    /// Attest a target TA by its identity
    ///
    /// # Arguments
    ///
    /// * `target_ta` - The identity (UUID) of the target TA to attest
    /// * `user_data` - Optional user data to include in the attestation
    ///
    /// # Returns
    ///
    /// An attestation report for the target TA
    fn attest_ta(&self, target_ta: &Identity, user_data: UserData) -> Result<AttestationReport>;

    /// Get the attestation public key
    fn get_attestation_pubkey(&self) -> Result<AttestationPubkey>;
}

/// Trait for managing signing keys and operations
pub trait AttestationKeyManagement {
    /// Sign the given data with the attestation key
    fn sign(&self, data: &[u8]) -> Result<AttestationSignature>;

    /// Get the attestation public key
    fn get_attestation_pubkey(&self) -> Result<AttestationPubkey>;
}

pub trait TaMeasurement {
    fn measure_ta(&self, target_ta: &Identity) -> Result<ReportBody>;
}

pub struct Attester<K: AttestationKeyManagement, M: TaMeasurement> {
    attestation_key_manager: K,
    ta_measurer: M,
}

impl<K: AttestationKeyManagement, M: TaMeasurement> Attester<K, M> {
    pub fn new(attestation_key_manager: K, ta_measurer: M) -> Self {
        Self {
            attestation_key_manager,
            ta_measurer,
        }
    }
}

impl<K: AttestationKeyManagement, M: TaMeasurement> Attesting for Attester<K, M> {
    fn attest_ta(&self, target_ta: &Identity, user_data: UserData) -> Result<AttestationReport> {
        // Create report body
        let body = self.ta_measurer.measure_ta(target_ta)?;

        // Create signing data
        let mut signing_data = body.signing_data();
        signing_data.extend_from_slice(user_data.as_bytes());

        // Sign the report
        let signature = self.attestation_key_manager.sign(&signing_data)?;

        Ok(AttestationReport::new(body, user_data, signature))
    }

    fn get_attestation_pubkey(&self) -> Result<AttestationPubkey> {
        self.attestation_key_manager.get_attestation_pubkey()
    }
}
