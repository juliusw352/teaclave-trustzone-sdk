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
use attestation::ReportBody;
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct MeasurementsRecorded(pub Vec<MeasurementRecord>);

#[derive(Debug, Serialize, Clone)]
pub struct MeasurementRecord {
    pub ta_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mr_ta_binary: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mr_ta_memory: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mr_os_memory: Option<[u8; 32]>,
}

impl<'de> Deserialize<'de> for MeasurementRecord {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MeasurementRecordVisitor;

        impl<'de> Visitor<'de> for MeasurementRecordVisitor {
            type Value = MeasurementRecord;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct MeasurementRecord")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<MeasurementRecord, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut ta_id = None;
                let mut mr_ta_binary = None;
                let mut mr_ta_memory = None;
                let mut mr_os_memory = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "ta_id" => {
                            ta_id = Some(map.next_value()?);
                        }
                        "mr_ta_binary" => {
                            let hex: Option<String> = map.next_value()?;
                            mr_ta_binary = hex.and_then(|h| parse_hex(&h).ok());
                        }
                        "mr_ta_memory" => {
                            let hex: Option<String> = map.next_value()?;
                            mr_ta_memory = hex.and_then(|h| parse_hex(&h).ok());
                        }
                        "mr_os_memory" => {
                            let hex: Option<String> = map.next_value()?;
                            mr_os_memory = hex.and_then(|h| parse_hex(&h).ok());
                        }
                        _ => {
                            let _ = map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }

                let ta_id = ta_id.ok_or_else(|| de::Error::missing_field("ta_id"))?;

                Ok(MeasurementRecord {
                    ta_id,
                    mr_ta_binary,
                    mr_ta_memory,
                    mr_os_memory,
                })
            }
        }

        deserializer.deserialize_map(MeasurementRecordVisitor)
    }
}

fn parse_hex(hex: &str) -> std::result::Result<[u8; 32], hex::FromHexError> {
    let bytes = hex::decode(hex)?;
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

impl MeasurementsRecorded {
    /// Find a measurement record by TA ID
    pub fn find_by_ta_id(&self, ta_id: &[u8; 16]) -> Option<&MeasurementRecord> {
        self.0
            .iter()
            .find(|record| record.ta_id.as_bytes() == ta_id)
    }
}

impl MeasurementRecord {
    pub fn compare_to_report_body(&self, report_body: &ReportBody) -> Result<()> {
        println!("[+] Verifying measurement record for TA ID {}", self.ta_id);

        // check the measurements
        if let Some(mr_ta_binary) = self.mr_ta_binary {
            ensure!(
                mr_ta_binary == report_body.mr_ta_binary,
                "MR TA binary mismatch, expected: {:?}, got: {:?}",
                mr_ta_binary,
                report_body.mr_ta_binary
            );
        }
        if let Some(mr_ta_memory) = self.mr_ta_memory {
            ensure!(
                mr_ta_memory == report_body.mr_ta_memory,
                "MR TA memory mismatch, expected: {:?}, got: {:?}",
                mr_ta_memory,
                report_body.mr_ta_memory
            );
        }
        if let Some(mr_os_memory) = self.mr_os_memory {
            ensure!(
                mr_os_memory == report_body.mr_os_memory,
                "MR OS memory mismatch, expected: {:?}, got: {:?}",
                mr_os_memory,
                report_body.mr_os_memory
            );
        }

        println!(
            "[+] Measurement record for TA ID {} checked successfully",
            self.ta_id
        );
        Ok(())
    }
}
