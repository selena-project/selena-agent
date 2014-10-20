#/usr/bin/env python


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



import socket
import CommandTools
import signal
import threading
import select
import sys
from NetHelper import NetHelper
#import sys, traceback

class ExpManagerClient(object):
    '''
    classdocs
    '''
    clientListeningPort = 55001
    serverListeningPort = 55002
    serverAddress = None
    serverRcvConnection = None
    serverSndConnection = None
    myNetHelper = None
    mySocket = None
    RCVBUFFSIZE = 4096
    RCV_TIMEOUT = 2
    CONN_TIMEOUT = 20
    myCmdExec = None
    clientListening = None
    clientThreads = []
    lock = None
    DELIMITER = "<|>"
    MESSAGE_SEPARATOR = "<#|#|#>"
    HOSTNAME = ""
    HOST_IP = ""
    currentRequest = None


    def __init__(self, pIpAddress=None):
        '''
        Constructor
        '''
        self.myCmdExec = CommandTools.CommandTools()
        self.myNetHelper = NetHelper()
        self.clientListening = False
        self.currentRequest = None
        self.HOSTNAME = socket.gethostname()
        if pIpAddress is None:
            self.HOST_IP = self.myNetHelper.getFirstNonLocalIP()
        else:
            if self.myNetHelper.isIPAddr(pIpAddress):
                self.HOST_IP = pIpAddress
            else:
                print "Address '%s' is not a valid IP address" % (pIpAddress)
                self.HOST_IP = self.myNetHelper.getFirstNonLocalIP()
        #socket.gethostbyname(self.HOSTNAME)
        self.lock = threading.RLock()
        signal.signal(signal.SIGTERM, self.handleSigTERM)
    
    def startListening(self):
        if self.clientListening:
            print "ExpManagerClient:Client has already started and is listening"
            return
        self.clientListening = True
        # Start listening for incoming server connections
        try:
            self.mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print "ExpManagerClient:Binding socket to " + self.HOST_IP + ":" + str(self.clientListeningPort) + "\n"
            self.mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.mySocket.bind((self.HOST_IP, self.clientListeningPort))
        except socket.error:
            print "ExpManagerClient:Client's server socket error. Terminating..."
            self.handleSigTERM()
            return
        try:
            # Wait for server to connect
            self.mySocket.listen(5)
            (tmpSocket, tmpAddress) = self.mySocket.accept()
            print "ExpManagerClient:The server with IP " + tmpAddress[0] + " has been connected."
            self.serverAddress = tmpAddress[0]
            self.serverRcvConnection = tmpSocket
            # Connect back to Server
            if not self.__connectToServer(self.serverAddress):
                self.handleSigTERM()
                return
            # Main loop
            self.serverRcvConnection.setblocking(0)
            while self.clientListening:
                # Start listening for new requests
                ready = select.select([self.serverRcvConnection], [], [], self.RCV_TIMEOUT)
                if ready[0]:
                    rcvMessage = self.serverRcvConnection.recv(self.RCVBUFFSIZE)
                    if rcvMessage == "":
                        print "ExpManagerClient:The server has closed the connection \n"
                        self.handleSigTERM()
                        return
                    retRequests = self.storeRequest(rcvMessage)
                    if not retRequests is None:
                        for tmpReq in retRequests:
                            if not tmpReq is None:
                                tmpThread = clientThread(tmpReq[0], tmpReq[1], tmpReq[2], self)
                                tmpThread.start()
                                self.clientThreads.append(tmpThread)
                # Cleanup terminated threads
                self.clientThreads = [t for t in self.clientThreads if t.isAlive()]
        except socket.timeout:
            #traceback.print_exc(file=sys.stdout)
            print "ExpManagerClient:Client's server socket has timed out. Terminating..."
            self.handleSigTERM()
        except socket.error as err:
            #traceback.print_exc(file=sys.stdout)
            print "ExpManagerClient:Error:\n" + str(err) + "\nClient's server socket error. Terminating..."
            self.handleSigTERM()
            
            
    def __connectToServer(self, serverAddr, pConnTimeout=None):
        if (serverAddr is None) or \
            (type(serverAddr) != str) or \
            ((not pConnTimeout is None) and (pConnTimeout < 1)):
            return False
        if pConnTimeout is None:
            pConnTimeout = self.CONN_TIMEOUT
        tmpSocket = None
        try:
            # Connect to the Client
            tmpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tmpSocket.settimeout(pConnTimeout)
            tmpSocket.bind((self.HOST_IP, 0))
            tmpSocket.connect((self.serverAddress, self.serverListeningPort))
            tmpSocket.settimeout(None)
            self.serverSndConnection = tmpSocket
        except socket.timeout:
            print "Unable to connect to server " + serverAddr + ". Connection timeout."
            if not tmpSocket is None:
                tmpSocket.shutdown(socket.SHUT_RDWR)
                tmpSocket.close()
            return False
        except socket.error:
            print "Unable to connect to server " + serverAddr + ". Socket error."
            if not tmpSocket is None:
                tmpSocket.shutdown(socket.SHUT_RDWR)
                tmpSocket.close()
            return False
        return True
            
            
    def processMessage(self, message):
        print "Processing the following message, received from server: \n" + message + "\n"
        fields = message.split(self.DELIMITER)
        if len(fields) != 3:
            print "Received a malformed message \n"
            return None
        try:
            seqNo = int(fields[0])
        except ValueError:
            print "Received a message with bad SEQNUM format \n"
            return None
        return [fields[0], fields[1], fields[2]]
    
    def storeRequest(self, pRequest):
        ret = None
        if len(pRequest.strip()) == 0:
            return ret
        if not self.MESSAGE_SEPARATOR in pRequest:
            if self.currentRequest is None:
                self.currentRequest = pRequest
            else:
                self.currentRequest += pRequest
        else:
            requests = pRequest.split(self.MESSAGE_SEPARATOR)
            lastItem = requests.pop(-1)
            for tmpReq in requests:
                if len(tmpReq.strip()) > 0:
                    if self.currentRequest is None:
                        self.currentRequest = tmpReq
                    else:
                        self.currentRequest += tmpReq
                    procMsg = self.processMessage(self.currentRequest)
                    self.currentRequest = None
                    if not procMsg is None:
                        if ret is None:
                            ret = [procMsg]
                        else:
                            ret.append(procMsg)
            if len(lastItem.strip()) > 0:
                self.currentRequest = lastItem
        return ret
    
    def cleanUpClientThreads(self):
        return True
    
    
    def sendResultsToServer(self, pSeqNumber, pResults):
        retVal = False
        if (not self.serverSndConnection is None):
            self.lock.acquire()
            sent = self.serverSndConnection.send(pSeqNumber + self.DELIMITER + pResults + self.MESSAGE_SEPARATOR)
            if sent == 0:
                print "Failed to send results back to server."
            else:
                print "Successfully sent results back to server"
                retVal = True
            self.lock.release()
        return retVal
    
    def handleSigTERM(self):
        if self.clientListening:
            print "\nHandling SIGTERM. Shutting down now..."
            self.clientListening = False
            self.mySocket.shutdown(socket.SHUT_RDWR)
            self.mySocket.close()
            for tmpThread in self.clientThreads:
                if (not tmpThread is None) and tmpThread.isAlive():
                    tmpThread.stop()
                self.clientThreads.remove(tmpThread)
            if not self.serverRcvConnection is None:
                self.serverRcvConnection.shutdown(socket.SHUT_RDWR)
                self.serverRcvConnection.close()
            if not self.serverSndConnection is None:
                self.serverSndConnection.shutdown(socket.SHUT_RDWR)
                self.serverSndConnection.close()



class clientThread(threading.Thread):
    
    def __init__(self, pSeqNum, pSendResults, pCommand, pClientObj):
        threading.Thread.__init__(self)
        self.seqNumber = pSeqNum
        self.commandToExec = pCommand
        self.clientObj = pClientObj
        self.doSendResults = (pSendResults != "0")
        self.EXEC = CommandTools.CommandTools()
        print("Client thread for serving request " + self.seqNumber + " has been created. . .")
        
    def run(self):
        print("Starting Client thread loop")
        (retStatus, outputStr) = self.EXEC.runCommand(self.commandToExec)
        if self.doSendResults and retStatus == 0:
            if not self.clientObj.sendResultsToServer(self.seqNumber, outputStr):
                print "Client could not send result back to server"
    
    def stop(self):
        print("Stopping Client thread\n\n")
        self.EXEC.stopAllProcesses()


    
if __name__ == "__main__":
    print 'This is ExpManagerClient module main'
    #myNetHelper = NetHelper.NetHelper()
    #print myNetHelper.get_default_gateway_linux()
    #print myNetHelper.isReachable("192.168.8.1", 22)
    try:
        theClient = ExpManagerClient(sys.argv[1])
        theClient.startListening()
    except KeyboardInterrupt:
            theClient.handleSigTERM()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
