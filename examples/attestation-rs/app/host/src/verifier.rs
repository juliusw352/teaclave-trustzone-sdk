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

use anyhow::{ensure, Result};
use attestation::{
    AttestationKeyEndorsement, AttestationPubkey, AttestationReport, EndorsementVerification,
    PlatformPubkey, ReportBody, ReportVerification, UserData,
};
use ring::signature;

use crate::measurements::MeasurementsRecorded;

/// ECDSA-based report verifier
pub struct EcdsaReportVerifier {
    pub user_data: UserData,
    pub measurements: MeasurementsRecorded,
}

impl EcdsaReportVerifier {
    pub fn check_report_body(&self, report: &ReportBody) -> Result<()> {
        println!("[+] Checking report body");

        // Find the measurement record for this specific TA ID
        if let Some(measurement) = self.measurements.find_by_ta_id(&report.ta_id) {
            measurement.compare_to_report_body(report)?;
        } else {
            println!(
                "[!] No measurement record found for TA ID: {:?}",
                report.ta_id
            );
            return Err(anyhow::anyhow!("No measurement record found for TA ID"));
        }

        println!("[+] Measurements checked successfully");

        println!("[+] Report body checked successfully");
        Ok(())
    }

    // Update the verifier with new measurements
    pub fn _update_measurements(&mut self, measurements: MeasurementsRecorded) -> Result<()> {
        println!("[+] Updating measurements");
        self.measurements = measurements;
        Ok(())
    }

    // Update the verifier with new user data
    pub fn _update_user_data(&mut self, user_data: UserData) -> Result<()> {
        println!("[+] Updating user data");
        self.user_data = user_data;
        Ok(())
    }
}

impl ReportVerification for EcdsaReportVerifier {
    fn verify_report(&self, ak_pub: &AttestationPubkey, report: &AttestationReport) -> Result<()> {
        println!("[+] Verifying report signature with ECDSA");

        let ak_pub = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            ak_pub.as_bytes(),
        );

        let data = report.signing_data();
        ak_pub
            .verify(&data, report.signature().as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to verify report signature: {:?}", e))?;

        println!("[+] Report signature verified successfully");

        // Check the user data
        let user_data = report.user_data();
        ensure!(
            user_data == &self.user_data,
            "User data does not match the expected value, expected: {:?}, got: {:?}",
            self.user_data,
            user_data
        );
        println!("[+] User data verified successfully");

        // Check the report body
        let report_body = report.report_body();
        self.check_report_body(report_body)?;
        println!("[+] Report body verified successfully");

        Ok(())
    }
}

/// ECDSA-based endorsement verifier
pub struct EcdsaEndorsementVerifier;

impl EndorsementVerification for EcdsaEndorsementVerifier {
    fn verify_endorsement(
        &self,
        platform_pk: &PlatformPubkey,
        endorsement: &AttestationKeyEndorsement,
    ) -> Result<()> {
        println!("[+] Verifying endorsement signature with ECDSA");

        let platform_pub = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            platform_pk.as_bytes(),
        );

        let hash = endorsement.signing_hash();

        platform_pub
            .verify(&hash, endorsement.signature().as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to verify endorsement signature: {:?}", e))?;

        println!("[+] Endorsement signature verified successfully");
        Ok(())
    }
}
