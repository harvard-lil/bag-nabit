#! /bin/bash
# script to regenerate files in test/fixtures/pki
set -euxo pipefail

# Create a directory for the test fixtures
mkdir -p test/fixtures/pki

# Generate ECDSA private key for root CA
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/pki/root-ca.key

# Create self-signed root certificate
openssl req -x509 -new -nodes \
  -key test/fixtures/pki/root-ca.key \
  -sha256 -days 3650 \
  -out test/fixtures/pki/root-ca.crt \
  -subj "/CN=Test Root CA/O=Data Vault Test/C=US"

# Generate ECDSA private key for intermediate CA
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/pki/intermediate-ca.key

# Create CSR for intermediate CA
openssl req -new \
  -key test/fixtures/pki/intermediate-ca.key \
  -out test/fixtures/pki/intermediate-ca.csr \
  -subj "/CN=Test Intermediate CA/O=Data Vault Test/C=US"

# Sign intermediate certificate with root CA
openssl x509 -req \
  -in test/fixtures/pki/intermediate-ca.csr \
  -CA test/fixtures/pki/root-ca.crt \
  -CAkey test/fixtures/pki/root-ca.key \
  -CAcreateserial \
  -out test/fixtures/pki/intermediate-ca.crt \
  -days 1825 \
  -sha256 \
  -extensions v3_ca \
  -extfile <(echo "[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyCertSign,cRLSign")

# Generate ECDSA private key for domain signing certificate
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/pki/domain-signing.key

# Create CSR for domain signing certificate
openssl req -new \
  -key test/fixtures/pki/domain-signing.key \
  -out test/fixtures/pki/domain-signing.csr \
  -subj "/CN=example.com/O=Data Vault Test/C=US"

# Sign domain end-entity certificate with intermediate CA
openssl x509 -req \
  -in test/fixtures/pki/domain-signing.csr \
  -CA test/fixtures/pki/intermediate-ca.crt \
  -CAkey test/fixtures/pki/intermediate-ca.key \
  -CAcreateserial \
  -out test/fixtures/pki/domain-signing.crt \
  -days 365 \
  -sha256 \
  -extensions v3_domain \
  -extfile <(echo "[v3_domain]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:example.com,DNS:www.example.com")

# Generate ECDSA private key for email signing certificate
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/pki/email-signing.key

# Create CSR for email signing certificate
openssl req -new \
  -key test/fixtures/pki/email-signing.key \
  -out test/fixtures/pki/email-signing.csr \
  -subj "/CN=user@example.com/O=Data Vault Test/C=US"

# Sign email end-entity certificate with intermediate CA
openssl x509 -req \
  -in test/fixtures/pki/email-signing.csr \
  -CA test/fixtures/pki/intermediate-ca.crt \
  -CAkey test/fixtures/pki/intermediate-ca.key \
  -CAcreateserial \
  -out test/fixtures/pki/email-signing.crt \
  -days 365 \
  -sha256 \
  -extensions v3_email \
  -extfile <(echo "[v3_email]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=emailProtection")

# Create the certificate chain files
cat test/fixtures/pki/domain-signing.crt test/fixtures/pki/intermediate-ca.crt test/fixtures/pki/root-ca.crt > test/fixtures/pki/domain-chain.pem
cat test/fixtures/pki/email-signing.crt test/fixtures/pki/intermediate-ca.crt test/fixtures/pki/root-ca.crt > test/fixtures/pki/email-chain.pem

# Clean up intermediate files
rm test/fixtures/pki/*.csr    # Remove Certificate Signing Requests
rm test/fixtures/pki/*.srl    # Remove serial number files

# Generated files:
# - root-ca.key             (Root CA private key)
# - root-ca.crt             (Root CA certificate)
# - intermediate-ca.key     (Intermediate CA private key)
# - intermediate-ca.crt     (Intermediate CA certificate)
# - domain-signing.key      (Domain signing private key)
# - domain-signing.crt      (Domain signing certificate)
# - domain-chain.pem        (Full certificate chain for domain cert)
# - email-signing.key       (Email signing private key)
# - email-signing.crt       (Email signing certificate)
# - email-chain.pem         (Full certificate chain for email cert)