#!/bin/bash

# Generates the throwaway TLS material the mock-oidc-tls suite needs.
#
# This replaces the two-level 4096-bit RSA chain the deleted keycloak suite built
# (see e2e/README.md). Everything here is 2048-bit and single-level, so the whole
# script runs in well under a second instead of tens of seconds.
#
# Two properties matter for the tests and are the reason this is not just
# `openssl req -x509` twice:
#
#   1. The leaf MUST be signed by a CA we also write out, because the suite feeds
#      exactly that CA (ca.pem) to the plugin as provider.cABundleFile. The
#      plugin appends the bundle to the system pool, so the leaf only verifies
#      if our CA is the one that signed it.
#   2. The mock IdP's own certificate MUST come from a PKCS12 keystore we
#      generate. mock-oauth2-server's built-in "ssl": {} defaults to a
#      self-signed certificate generated at boot, whose CA differs on every run
#      and could therefore never be handed to cABundle. Only a keystore we made
#      keeps the CA stable across runs.

set -euo pipefail

# The script is invoked as ./gencerts.sh from whatever directory bun happens to
# be in, and every path below is relative, so anchor on the script's own
# directory instead of $PWD.
cd "$(dirname "$0")"

CERT_DIR="./certificates"

rm -rf "${CERT_DIR}"
mkdir -p "${CERT_DIR}"

# --- Test CA -------------------------------------------------------------
# Self-signed, CA:TRUE. ca.pem is what the positive tests hand to the plugin.
CA_KEY="${CERT_DIR}/ca.key"
CA_CERT="${CERT_DIR}/ca.pem"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${CA_KEY}" 2>/dev/null
openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
    -out "${CA_CERT}" \
    -subj "/O=Mock OIDC Test/CN=Mock OIDC Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "CA created:            ${CA_CERT}"

# --- Leaf certificate for CN=localhost -----------------------------------
# SANs cover both spellings the tests use: the plugin inside the traefik
# container reaches the mock through the extra_hosts alias `localhost`, and the
# liveness guard connects to 127.0.0.1:8443 directly.
LEAF_KEY="${CERT_DIR}/website.key"
LEAF_CSR="${CERT_DIR}/website.csr"
LEAF_CERT="${CERT_DIR}/website.pem"
LEAF_EXT="${CERT_DIR}/website.ext"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${LEAF_KEY}" 2>/dev/null
openssl req -new -key "${LEAF_KEY}" -out "${LEAF_CSR}" \
    -subj "/O=Mock OIDC Test/CN=localhost"

cat >"${LEAF_EXT}" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in "${LEAF_CSR}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${LEAF_CERT}" -days 3650 -sha256 -extfile "${LEAF_EXT}"

echo "Leaf certificate:      ${LEAF_CERT}"

# --- PKCS12 keystore handed to the mock IdP ------------------------------
# Empty password on both the store and the key: config.json sets
# keystorePassword "" and keyPassword "", which are the mock's defaults, so the
# keystore has to match or the container never boots.
# -certfile puts the CA in the chain so the store is self-describing.
openssl pkcs12 -export -out "${CERT_DIR}/mock_oidc.p12" \
    -inkey "${LEAF_KEY}" -in "${LEAF_CERT}" -certfile "${CA_CERT}" \
    -passout pass:
# nginx's ssl_certificate wants the leaf AND the issuing CA, so the client can
# build a path without needing the CA from anywhere else. The plugin is given the
# CA separately via cABundle, but sending the chain keeps the file usable by any
# other TLS client in the suite (and keeps openssl s_client happy).
cat "${LEAF_CERT}" "${CERT_DIR}/ca.pem" > "${CERT_DIR}/fullchain.pem"

echo "PKCS12 keystore:       ${CERT_DIR}/mock_oidc.p12"

# --- Unrelated CA for the negative test ----------------------------------
# T4 hands THIS CA to the plugin. It is a perfectly valid CA that did not sign
# the leaf, which is the point: the bundle loads and is applied, but the TLS
# handshake still fails. other_ca.pem must NOT be the only thing in
# certificates/ that could verify the leaf - it must never be able to.
OTHER_CA_KEY="${CERT_DIR}/other_ca.key"
OTHER_CA_CERT="${CERT_DIR}/other_ca.pem"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${OTHER_CA_KEY}" 2>/dev/null
openssl req -x509 -new -nodes -key "${OTHER_CA_KEY}" -sha256 -days 3650 \
    -out "${OTHER_CA_CERT}" \
    -subj "/O=Mock OIDC Test/CN=Unrelated Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "Unrelated CA:          ${OTHER_CA_CERT}"

rm -f "${LEAF_CSR}" "${LEAF_EXT}"

# The mock-oauth2-server image runs as a non-root user, and both /certificates
# mounts are read-only, so every file has to be world-readable and the
# directory traversable.
chmod 755 "${CERT_DIR}"
find "${CERT_DIR}" -type f -exec chmod 644 {} +

cat <<EOF

Certificates created successfully:
- CA (use as cABundleFile): ${CA_CERT}
- Leaf (CN=localhost):       ${LEAF_CERT}
- PKCS12 keystore:           ${CERT_DIR}/mock_oidc.p12 (store and key password are both empty)
- Unrelated CA (T4):         ${OTHER_CA_CERT}
EOF