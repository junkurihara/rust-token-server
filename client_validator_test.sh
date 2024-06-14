#!/bin/bash

ADMIN_NAME=admin
ADMIN_PASSWORD=admin_password_1234
CLIENT_ID=client_id1
TOKEN_ENDPOINT=http://localhost:3000/v1.0
CLIENT_DB_PATH=/tmp/users_test.db
ID_TOKEN_ENV=/tmp/id_token.env

cargo build --package rust-token-server

pgrep -f rust-token-server | xargs kill -9

######################
echo "ES256"
ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  ./target/debug/rust-token-server run \
  --token-issuer=${TOKEN_ENDPOINT} \
  --client-ids=${CLIENT_ID} \
  --signing-key-path=./server/sample-keys/p256.private_key.pem \
  --db-file-path=${CLIENT_DB_PATH} &

sleep 5

######################
echo "lib-client"
RUST_LOG=debug \
  ADMIN_NAME=${ADMIN_NAME}\
  ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  CLIENT_ID=${CLIENT_ID}\
  TOKEN_ENDPOINT=${TOKEN_ENDPOINT}\
  cargo test --package rust-token-server-client -- --nocapture

######################
echo "lib-validator"
curl -X POST -H "Content-Type: application/json" \
  -d "{ \"auth\": {\"username\": \"${ADMIN_NAME}\", \"password\": \"${ADMIN_PASSWORD}\" },  \"client_id\": \"${CLIENT_ID}\" }" \
  ${TOKEN_ENDPOINT}/tokens | jq '.token.id' | xargs echo > ${ID_TOKEN_ENV}

RUST_LOG=debug \
  ID_TOKEN_ENV=${ID_TOKEN_ENV} \
  ADMIN_NAME=${ADMIN_NAME}\
  ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  CLIENT_ID=${CLIENT_ID}\
  TOKEN_ENDPOINT=${TOKEN_ENDPOINT}\
  TOKEN_ISSUER=${TOKEN_ENDPOINT}\
  cargo test --package rust-token-server-validator -- --nocapture

pgrep -f rust-token-server | xargs kill -9

rm ${CLIENT_DB_PATH}
rm ${ID_TOKEN_ENV}

sleep 5

######################
echo "Ed25519"
ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  ./target/debug/rust-token-server run \
  --token-issuer=${TOKEN_ENDPOINT} \
  --client-ids=${CLIENT_ID} \
  --signing-key-path=./server/sample-keys/ed25519.private_key.pem \
  --db-file-path=${CLIENT_DB_PATH}  &

sleep 5

######################
echo "lib-client"
ADMIN_NAME=${ADMIN_NAME}\
  ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  CLIENT_ID=${CLIENT_ID}\
  TOKEN_ENDPOINT=${TOKEN_ENDPOINT}\
  cargo test --package rust-token-server-client -- --nocapture

######################
echo "lib-validator"
curl -X POST -H "Content-Type: application/json" \
  -d "{ \"auth\": {\"username\": \"${ADMIN_NAME}\", \"password\": \"${ADMIN_PASSWORD}\" },  \"client_id\": \"${CLIENT_ID}\" }" \
  ${TOKEN_ENDPOINT}/tokens | jq '.token.id' | xargs echo > ${ID_TOKEN_ENV}

RUST_LOG=debug \
  ID_TOKEN_ENV=${ID_TOKEN_ENV} \
  ADMIN_NAME=${ADMIN_NAME}\
  ADMIN_PASSWORD=${ADMIN_PASSWORD}\
  CLIENT_ID=${CLIENT_ID}\
  TOKEN_ENDPOINT=${TOKEN_ENDPOINT}\
  TOKEN_ISSUER=${TOKEN_ENDPOINT}\
  cargo test --package rust-token-server-validator -- --nocapture

pgrep -f rust-token-server | xargs kill -9
rm ${CLIENT_DB_PATH}
rm ${ID_TOKEN_ENV}
