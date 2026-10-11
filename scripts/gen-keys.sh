#!/usr/bin/env sh
# Generates the RSA key pair used to sign (auth-service) and verify (api-service) JWTs.
set -eu
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private.pem
openssl pkey -in keys/private.pem -pubout -out keys/public.pem
# Dev only: containers run as non-root, so the mounted files must be world-readable.
chmod 644 keys/private.pem keys/public.pem
echo "keys written to ./keys"
