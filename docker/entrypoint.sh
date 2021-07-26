#!/usr/bin/env bash

echo "start token server"

# read custom configuration
source /opt/token-server/etc/.env

# echo "doh-proxy: upstream dns server address: ${UPSTREAM_ADDR}:${UPSTREAM_PORT}"

echo "init first"
/opt/token-server/sbin/rust-token-server init \
  --admin-name ${ADMIN_NAME} \
  --admin-password ${ADMIN_PASSWORD} \
  --db-file-path /opt/token-server/etc/userdb.db

echo "run the server"
ROCKET_ENV=production \
ROCKET_ADDRESS=0.0.0.0 \
ROCKET_PORT=8000 \
/opt/token-server/sbin/rust-token-server run \
  --signing-algorithm ${SIGNING_ALGORITHM} \
  --signing-key-path /opt/token-server/etc/private_key.pem \
  --db-file-path /opt/token-server/etc/userdb.db
