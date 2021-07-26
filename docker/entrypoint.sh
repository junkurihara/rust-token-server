#!/usr/bin/env bash

echo "start token server"

# read custom configuration
source /opt/token-server/etc/.env

echo "init first"
RUST_LOG=debug /opt/token-server/sbin/rust-token-server init \
  --admin-name ${ADMIN_NAME} \
  --admin-password ${ADMIN_PASSWORD} \
  --db-file-path /opt/token-server/var/userdb.db

echo "run the server"
RUST_LOG=debug \
ROCKET_ENV=development \
ROCKET_ADDRESS="0.0.0.0" \
ROCKET_PORT=8000 \
/opt/token-server/sbin/rust-token-server run \
  --signing-algorithm ${SIGNING_ALGORITHM} \
  --signing-key-path /opt/token-server/etc/private_key.pem \
  --db-file-path /opt/token-server/var/userdb.db
