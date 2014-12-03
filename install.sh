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

UPDATE_INIT=`which update-rc.d`
[[ $? -eq 0 ]] || { echo "*** Couldn't find 'update-rc.d'. Make sure it is instaled on your system."; exit 1; }

# Checking whether Selena agent init script is already installed"
[[ -f ${INIT_DIR_DEST}/${SELENA_SVC} ]] && { echo "Selena agent init script is already installed. Run uninstall first"; exit 1; }
[[ -f ${BIN_DIR_DEST}/${SELENA_SVC} ]] && { echo "Selena agent executable is already installed. Run uninstall first"; exit 1; }

# Copy the selena agent init script
cp ${INIT_SCRIPT} ${INIT_DIR_DEST}
[[ $? -eq 0 ]] || { echo "*** Failed to copy selena init script in ${INIT_DIR_DEST}."; exit 1; }
chmod +x ${INIT_DIR_DEST}/${SELENA_SVC}
[[ $? -eq 0 ]] || { echo "*** Failed to give selena init script execution rights (${INIT_DIR_DEST}/${SELENA_SVC})."; exit 1; }


# Copy the selena agent bin script
cp ${BIN_SCRIPT} ${BIN_DIR_DEST}
[[ $? -eq 0 ]] || { echo "*** Failed to copy selena executable script in ${BIN_DIR_DEST}."; exit 1; }
chmod +x ${BIN_DIR_DEST}/${SELENA_BIN}
[[ $? -eq 0 ]] || { echo "*** Failed to give selena script execution rights (${BIN_DIR_DEST}/${SELENA_BIN})."; exit 1; }

# Install the service
${UPDATE_INIT} ${SELENA_SVC} defaults
[[ $? -eq 0 ]] || { echo "*** Failed to configure selena daemon to start on boot."; exit 1; }


echo "*** Done"
