#!/usr/bin/env bash

LOG_FILE=/var/log/token-server/token-server.log
LOG_SIZE=10M
LOG_NUM=10

# logrotate
if [ $LOGROTATE_NUM ]; then
  LOG_NUM=${LOGROTATE_NUM}
fi
if [ $LOGROTATE_SIZE ]; then
  LOG_SIZE=${LOGROTATE_SIZE}
fi

cat > /etc/logrotate.conf << EOF
# see "man logrotate" for details
# rotate log files weekly
weekly
# use the adm group by default, since this is the owning group
# of /var/log/syslog.
su root adm
# keep 4 weeks worth of backlogs
rotate 4
# create new (empty) log files after rotating old ones
create
# use date as a suffix of the rotated file
#dateext
# uncomment this if you want your log files compressed
#compress
# packages drop log rotation information into this directory
include /etc/logrotate.d
# system-specific logs may be also be configured here.
EOF

cat > /etc/logrotate.d/token-server << EOF
${LOG_FILE} {
    dateext
    daily
    missingok
    rotate ${LOG_NUM}
    notifempty
    compress
    delaycompress
    dateformat -%Y-%m-%d-%s
    size ${LOG_SIZE}
    copytruncate
}
EOF

cp -p /etc/cron.daily/logrotate /etc/cron.hourly/
service cron start

echo "Start ID Token Server"

# read custom configuration
source /opt/token-server/etc/.env

# debug level logging
LOG_LEVEL=info
if [ ${DEBUG} ]; then
  echo "Logging in debug mode"
  LOG_LEVEL=debug
fi

# read custom configuration
source /opt/token-server/etc/.env

echo "Init first"
RUST_LOG=${LOG_LEVEL} /opt/token-server/sbin/rust-token-server init \
  --admin-name ${ADMIN_NAME} \
  --admin-password ${ADMIN_PASSWORD} \
  --db-file-path /opt/token-server/var/userdb.db \
  --client-ids ${CLIENT_IDS}

echo "Run the server"
RUST_LOG=${LOG_LEVEL} \
ROCKET_ENV=development \
ROCKET_ADDRESS="0.0.0.0" \
ROCKET_PORT=8000 \
/opt/token-server/sbin/rust-token-server run \
  --signing-algorithm ${SIGNING_ALGORITHM} \
  --signing-key-path /opt/token-server/etc/private_key.pem \
  --db-file-path /opt/token-server/var/userdb.db \
  --token-issuer ${TOKEN_ISSUER} \
  --with-key-id
