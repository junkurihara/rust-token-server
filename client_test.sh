#!/bin/bash

ADMIN_NAME=admin
ADMIN_PASSWORD=admin_password_1234
CLIENT_ID=client_id1
TOKEN_ENDPOINT=http://localhost:3000/v1.0
CLIENT_DB_PATH=/tmp/users_test.db

cargo build --package rust-token-server

echo "ES256"
ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  ./target/debug/rust-token-server run \
  --token-issuer=${TOKEN_ENDPOINT} \
  --client-ids=${CLIENT_ID} \
  --signing-key-path=./server/sample-keys/p256.private_key.pem \
  --signing-algorithm=ES256 \
  --db-file-path=${CLIENT_DB_PATH} \
  --with-key-id &

sleep 3

ADMIN_NAME=${ADMIN_NAME}\
  ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  CLIENT_ID=${CLIENT_ID}\
  TOKEN_ENDPOINT=${TOKEN_ENDPOINT}\
  cargo test --package rust-token-server-client -- --nocapture

pgrep -f rust-token-server | xargs kill -9
rm ${CLIENT_DB_PATH}

echo "Ed25519"
ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  ./target/debug/rust-token-server run \
  --token-issuer=${TOKEN_ENDPOINT} \
  --client-ids=${CLIENT_ID} \
  --signing-key-path=./server/sample-keys/ed25519.private_key.pem \
  --signing-algorithm=EdDSA \
  --db-file-path=${CLIENT_DB_PATH} \
  --with-key-id &

sleep 3

ADMIN_NAME=${ADMIN_NAME}\
  ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  CLIENT_ID=${CLIENT_ID}\
  TOKEN_ENDPOINT=${TOKEN_ENDPOINT}\
  cargo test --package rust-token-server-client -- --nocapture

pgrep -f rust-token-server | xargs kill -9
rm ${CLIENT_DB_PATH}
