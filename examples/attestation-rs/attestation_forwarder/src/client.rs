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

extern crate alloc;

use alloc::vec::Vec;
use optee_utee::{
    trace_println, Error, ErrorKind, ParamIndex, Parameters, Result, TaSessionBuilder, TeeParams,
    Uuid,
};
use quoting_ta_proto::{QuotingTaCommand, MAX_OUTPUT_SIZE};

/// Service for handling attestation operations.
/// Provides a clean interface for getting quotes from the Quoting TA.
pub struct QuotingTaClient {
    quoting_ta_uuid: Uuid,
}

impl QuotingTaClient {
    /// Creates a new instance of QuotingTaClient
    pub fn init(quoting_ta_uuid: Uuid) -> Result<Self> {
        Ok(Self { quoting_ta_uuid })
    }

    /// Gets a quote from the Quoting TA.
    ///
    /// This is the main entry point for developers who want to get quotes for their TAs.
    ///
    /// # Arguments
    /// * `params` - Parameters from the TA invocation. Expected format:
    ///   - params.0: Input buffer containing user data
    ///   - params.1: Output buffer where the quote will be written
    ///
    /// # Returns
    /// * `Result<()>` - Ok if quote was successfully generated and written to output buffer
    ///
    /// # Example
    /// ```no_run
    /// fn ta_invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    ///     match cmd_id {
    ///         CMD_GET_QUOTE => {
    ///             let service = QuotingTaClient::init();
    ///             service.get_quote(params)
    ///         },
    ///         _ => Err(Error::new(ErrorKind::NotSupported)),
    ///     }
    /// }
    /// ```
    pub fn get_quote(&self, params: &mut Parameters) -> Result<()> {
        trace_println!("QuotingTaClient: get quote");
        // Extract input and output buffers
        let mut p0 = unsafe { params.0.as_memref().unwrap() };
        let mut p1 = unsafe { params.1.as_memref().unwrap() };

        // Get quote from Quoting TA
        let quote = self.get_quote_from_ta(p0.buffer()).map_err(|e| {
            trace_println!("[!] Failed to get quote: {:?}", e);
            Error::new(ErrorKind::BadParameters)
        })?;

        // Write quote to output buffer
        self.write_quote_to_buffer(&quote, p1.buffer())
            .map_err(|e| {
                trace_println!("[!] Failed to write quote: {:?}", e);
                Error::new(ErrorKind::BadParameters)
            })?;

        trace_println!("[+] Quote successfully generated and written");
        Ok(())
    }

    /// Internal function to get a quote from the Quoting TA
    fn get_quote_from_ta(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        // Initialize session with Quoting TA
        let mut session = TaSessionBuilder::new(self.quoting_ta_uuid).build()?;

        // Prepare parameters for the quote request
        let mut output_quote = [0u8; MAX_OUTPUT_SIZE];
        let mut params = TeeParams::new()
            .with_memref_in(ParamIndex::Arg0, user_data)
            .with_memref_out(ParamIndex::Arg1, &mut output_quote);

        // Get quote from Quoting TA
        session.invoke_command(QuotingTaCommand::GetQuote as u32, &mut params)?;

        // Extract quote from output buffer
        let output = params[ParamIndex::Arg1]
            .written_slice()
            .map(|slice| slice.to_vec())
            .ok_or_else(|| Error::new(ErrorKind::BadParameters))?;
        Ok(output)
    }

    /// Internal function to write quote to output buffer
    fn write_quote_to_buffer(&self, quote: &[u8], buffer: &mut [u8]) -> Result<()> {
        if quote.len() > buffer.len() {
            trace_println!("[!] Output buffer too small for quote");
            return Err(Error::new(ErrorKind::BadParameters));
        }

        buffer[..quote.len()].copy_from_slice(quote);
        Ok(())
    }
}
