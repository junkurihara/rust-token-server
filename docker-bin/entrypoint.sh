#!/usr/bin/env bash
LOG_FILE=/var/log/token-server/token-server.log

/run.sh 2>&1 | tee $LOG_FILE
