#!/usr/bin/env bash

# ---------------------------------------------------------------------
#   Copyright (C) 2014 Dimosthenis Pediaditakis, Charalampos Rotsos.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
#   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
#   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
#---------------------------------------------------------------------

if [ "$(id -u)" != "0" ]; then
        echo "Sorry, you are not root."
        exit 1
fi


INIT_DIR_DEST=/etc/init.d
BIN_DIR_DEST=/usr/bin

INIT_SCRIPT=./init.d_script/selena
BIN_SCRIPT=./bin/selena_agent.py

SELENA_SVC=`basename ${INIT_SCRIPT}`
SELENA_BIN=`basename ${BIN_SCRIPT}`


# Stop the selena agent from starting on boot
command -v update-rc.d >/dev/null 2>&1 || { echo "*** Couldn't find 'update-rc.d'. Make sure it is installed on your system."; exit 1; }
update-rc.d ${SELENA_SVC} remove

# Stop any running instances of Selena
service ${SELENA_SVC} status | grep running
[[ $? -eq 0 ]] && {  echo "*** Stopping gracefully the selena agent process (SIGTERM)"; service ${SELENA_SVC} stop; }
PID=`ps aux | grep python | grep ${SELENA_BIN} | awk '{print $2}'`
[[ -n "${PID}" ]] && { echo "*** Force-killing the selena agent process (SIGKILL)"; kill -9 ${PID}; }


# Remove the init script and the executable
[[ -f ${INIT_DIR_DEST}/${SELENA_SVC} ]] && rm ${INIT_DIR_DEST}/${SELENA_SVC}
[[ -f ${BIN_DIR_DEST}/${SELENA_BIN} ]] && rm ${BIN_DIR_DEST}/${SELENA_BIN}


echo "*** DONE"

