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

use anyhow::{anyhow, Result};
use attestation::{AttestationKeyEndorsement, AttestationPubkey, EndorsementStore};
use optee_utee::trace_println;
use secure_db::{SecureStorageClient, Storable};
use serde::{Deserialize, Serialize};

const ENDORSEMENT_DB_NAME: &str = "endorsement_db";

// Define a new type wrapper for AttestationKeyEndorsement
// Because Storable and AttestationKeyEndorsement are not from this crate,
// we cannot derive Storable for AttestationKeyEndorsement directly.
#[derive(Serialize, Deserialize)]
pub struct StorableAttestationKeyEndorsement(pub AttestationKeyEndorsement);

impl Storable for StorableAttestationKeyEndorsement {
    type Key = String;

    fn unique_id(&self) -> Self::Key {
        // hash of AttestationPubkey
        hex::encode(self.0.attestation_pubkey().hash())
    }
}

/// Local implementation of EndorsementStore using secure storage
pub struct LocalEndorsementStore {
    db_client: SecureStorageClient,
}

impl LocalEndorsementStore {
    pub fn init() -> Result<Self> {
        trace_println!("[+] Initializing LocalEndorsementStore");
        let db_client = SecureStorageClient::open(ENDORSEMENT_DB_NAME)
            .map_err(|e| anyhow!("Failed to open secure storage: {:?}", e))?;

        Ok(Self { db_client })
    }
}

impl EndorsementStore for LocalEndorsementStore {
    fn get_endorsement(
        &self,
        attestation_pubkey: &AttestationPubkey,
    ) -> Option<AttestationKeyEndorsement> {
        let attestation_pubkey_hash_as_storage_key = hex::encode(attestation_pubkey.hash());

        match self
            .db_client
            .get::<StorableAttestationKeyEndorsement>(&attestation_pubkey_hash_as_storage_key)
        {
            Ok(endorsement) => {
                trace_println!("[+] Found endorsement in store");
                Some(endorsement.0)
            }
            Err(e) => {
                trace_println!("[-] Failed to get endorsement: {:?}", e);
                None
            }
        }
    }

    fn store_endorsement(&self, endorsement: AttestationKeyEndorsement) -> Result<()> {
        self.db_client
            .put(&StorableAttestationKeyEndorsement(endorsement))
            .map_err(|e| anyhow!("Failed to store endorsement: {:?}", e))?;

        trace_println!("[+] Successfully stored endorsement");
        Ok(())
    }
}
