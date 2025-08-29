#!/bin/bash

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# Script to generate test keys for the attestation example
# This script generates a new ECDSA P-256 key pair for testing purposes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Generating test ECDSA P-256 key pair..."

# Generate private key in PEM format
openssl ecparam -genkey -name prime256v1 -noout -out platform_key.private

# Convert private key to DER format (PKCS#8)
openssl pkcs8 -topk8 -inform PEM -outform DER -in platform_key.private -out platform_key.der -nocrypt

# Extract public key and convert to hex format
openssl ec -in platform_key.private -pubout -outform DER | tail -c 65 | xxd -p -c 65 | tr -d '\n' > platform_key.pub

echo "Test keys generated successfully:"
echo "  platform_key.private - Private key (PEM format) "
echo "  platform_key.der     - Private key (DER format) "
echo "  platform_key.pub     - Public key (hex format) -  verifier reads this file through cli"
echo ""
echo "WARNING: These are test keys only. For production use, keys should be:"
echo "  - Generated in secure hardware (HSM/TPM)"
echo "  - Stored in secure storage"
echo "  - Never exposed in source code"
