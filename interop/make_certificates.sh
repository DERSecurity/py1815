#!/usr/bin/env bash
# Make the certificates the interoperability job uses for TLS: an authority,
# and a certificate and key each for the outstation and for the master.
#
# They are made new for each run and last a day. Nothing this script writes is
# ever committed: give it a directory outside the checkout.
#
# The outstation's certificate names outstation.test and the master's names
# master.test. Neither names an address, so the master is told the name to
# check (--tls-server-name) and the outstation is told the name to accept.
#
# Usage:
#   interop/make_certificates.sh DIRECTORY
#
# Writes authority.pem, outstation.pem, outstation.key, master.pem and
# master.key into DIRECTORY.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 DIRECTORY" >&2
  exit 2
fi

mkdir -p "$1"
cd "$1"
umask 077

# Every extension is stated here, so the result does not depend on the
# openssl.cnf of the machine. A verifier in strict mode refuses an authority
# with no key usage and a certificate with no authority key identifier.
cat > openssl.cnf <<'EOF'
[req]
distinguished_name = name
prompt = no

[name]
CN = py1815 interoperability test

[authority]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[outstation]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:outstation.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[master]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:master.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

openssl req -x509 -config openssl.cnf -extensions authority -newkey rsa:2048 -nodes \
  -sha256 -days 1 -subj "/CN=py1815 interoperability test authority" \
  -keyout authority.key -out authority.pem

for who in outstation master; do
  openssl req -new -config openssl.cnf -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=$who.test" -keyout "$who.key" -out "$who.csr"
  openssl x509 -req -in "$who.csr" -CA authority.pem -CAkey authority.key \
    -CAcreateserial -sha256 -days 1 -extfile openssl.cnf -extensions "$who" \
    -out "$who.pem"
done

# Only the five files named above are needed from here on. The authority's key
# in particular has signed everything it will ever sign.
rm -f authority.key authority.srl outstation.csr master.csr openssl.cnf
