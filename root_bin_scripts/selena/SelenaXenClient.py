# -*- coding: utf-8 -*-
#---------------------------------------------------------------------
#   Copyright (C) 2014 Dimosthenis Pediaditakis.
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


from ExpManagerClient import ExpManagerClient
from CommandTools import CommandTools
import sys
import time
import threading

MANAGEMENT_IFACE = 'eth0'

def checkCmdExitStatus(pStatus, pMessage):
    if pStatus:
        print "ERROR: " + pMessage 
        sys.exit(1)


theClient = None
EXEC=CommandTools()
stopXS=False

def startXenstoreService():
	print "Starting the selena remote-command service" 
    	while not stopXS:
	    (status, _) = EXEC.runCommand('xenstore-exists Selena/cmd')
	    if status:
		    time.sleep(2)
	    else:
		    # Wait for an incoming command
		    (_, _) = EXEC.runCommand('xenstore-watch -n 2 Selena/cmd')
		    (status, rcvCmd) = EXEC.runCommand('xenstore-read Selena/cmd')
		    if not status:
			    print 'Received command:' + rcvCmd + '\n'
			    (status, output) = EXEC.runCommand(rcvCmd)
			    if len(output) > 4090:
				    output = output[:4089] 
			    #print 'xenstore-write Selena/response ' + output
			    #print 'xenstore-write Selena/lock FREE'
			    (_, _) = EXEC.runCommand('xenstore-write Selena/response \'' + output + '\'')
			    (_, _) = EXEC.runCommand('xenstore-write Selena/lock FREE')
		    else:
			    print 'Failed to read command from Xenstore'



if __name__ == '__main__':
    print "This is SelenaXenClient"
    
    # Read the management ipaddress
    (status, mgmtIPAddress) = EXEC.runCommand('xenstore-read Selena/bootipaddr')
    checkCmdExitStatus(status, "Could not read management IP address from xenstore")
    mgmtIPAddress = mgmtIPAddress.strip()
    
    # Read the management netmask
    (status, netmask) = EXEC.runCommand('xenstore-read Selena/bootipmask')
    checkCmdExitStatus(status, "Could not read management IP net mask from xenstore")
    netmask = netmask.strip()

    # Configure the management interface
    (status, out) = EXEC.runCommand('ifconfig ' + MANAGEMENT_IFACE + ' ' + mgmtIPAddress + ' netmask ' + netmask)
    checkCmdExitStatus(status, "Could not configure the management interface: \n" + 'ifconfig ' + MANAGEMENT_IFACE + ' ' + mgmtIPAddress + ' netmask ' + netmask)
    
    (status, out) = EXEC.runCommand('xenstore-write Selena/lock FREE')
    checkCmdExitStatus(status, "Could not update the Selena/lock key in xenstore")

    t1 = threading.Thread( target=startXenstoreService )
    t1.start()

    try:
	print "Starting a new ExpManagerClient instance"
	theClient = ExpManagerClient(mgmtIPAddress)
	theClient.startListening()
    except KeyboardInterrupt:
	stopXS = True
	if theClient:
		theClient.handleSigTERM()



