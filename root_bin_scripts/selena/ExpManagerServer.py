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
from threading import Thread,Condition,RLock
import signal
import select
from collections import deque
import time
from NetHelper import NetHelper
import os
#from pprint import pprint
#import sys, traceback

class ExpManagerServer(Thread):
    '''
    classdocs
    '''
    MSG_TYPE = {'HELLO':0,
                'BYE':1,
                'RESPONSE':2,
                'END_OF_RESPONSE':3,
                'RUNCOMMAND':4,
                'IPERFSERVER':5,
                'IPERFCLIENT':6,
                'WBESTSERVER':7,
                'WBESTCLIENT':8}
    # ----- CONSTANTS  ------
    MIN_CMD_LEN = 2
    SELECT_TIMEOUT = 2
    CONNECT_TIMEOUT = 20
    DELIMITER = "<|>"
    MESSAGE_SEPARATOR = "<#|#|#>"
    RCVBUFFSIZE = 4096
    MIN_MESSAGE_LEN = 5
    HOSTNAME = ""
    HOST_IP = ""
    clientListeningPort = 55001
    serverListeningPort = 55002
    #clientAddresses = {"eeePC":"192.168.8.1", 
    #                   "x121e":"192.168.10.1", 
    #                   "speed":"192.168.10.1", 
    #                   "mediaSvr":"192.168.10.1"}
    #clientAddresses = {"vaioZ":"192.168.8.2"}
    clientAddresses = None#{"cosmic":"128.232.10.197"}

    # ----- MEMBER VARS  ------
    serverSocketThread = None
    serverSocket = None
    serverIsRunning = False
    clientPushThreads = {}
    clientRcvThreads = {}
    lockServerRequests = None
    lockClientThreadsUpdate = None
    currSeqNum = 0
    sentRequests = {}
    myNetHelper = None


    def __init__(self, pIpAddress=None):
        Thread.__init__(self)
        '''
        Constructor
        '''
        self.lockServerRequests = RLock()
        self.lockClientThreadsUpdate = RLock()
        self.serverSocketThread = None
        self.serverSocket = None
        self.serverIsRunning = False
        self.currSeqNum = 0
        self.myNetHelper = NetHelper()
        self.HOSTNAME = socket.gethostname()
        if pIpAddress is None:
            self.HOST_IP = self.myNetHelper.getFirstNonLocalIP()
        else:
            if self.myNetHelper.isIPAddr(pIpAddress):
                self.HOST_IP = pIpAddress
            else:
                print "Address '%s' is not a valid IP address" % (pIpAddress)
                self.HOST_IP = self.myNetHelper.getFirstNonLocalIP()
        self.clientAddresses = {}
        #for k in self.clientAddresses.keys():
        #    self.clientPushThreads[k] = None
        #    self.clientRcvThreads[k] = None
        #socket.gethostbyname(self.HOSTNAME)
        
    def run(self):
        if self.serverIsRunning:
            print "ExpManagerServer: The server is already running\n"
            return
        #if len(self.clientAddresses.keys()) == 0:
        #    print "ExpManagerServer: Empty clients list. Coudln't start\n"
        #    return
        # Start the Server socket thread, accepting new Client connections
        self.serverSocketThread = serverSocketThread(self)
        self.serverSocketThread.start()
        self.serverIsRunning = True
        # Connect to each Client, expect them to connect back
        #for k in self.clientAddresses.keys():
        #    # Start a new push=thread and connect to cLient
        #    tmpClientPushThread = clientPushThread(k, self)
        #    self.lockClientThreadsUpdate.acquire()
        #    self.clientPushThreads[k] = tmpClientPushThread
        #    self.lockClientThreadsUpdate.release()
        #    tmpClientPushThread.start()
        print "ExpManagerServer: KILLED !!!!!!!!!!\n"
        
    def createClientReceiveThread(self, pSocket, pClientName):
        if (type(pSocket) != socket._socketobject) or (type(pClientName) != str):
            print "ExpManagerServer: createClientReceiveThread: The supplied arguments have incorrect type\n"
            return False
        # Start a new thread for receiving data from CLient
        tmpClientRcvThread = clientReceiveThread(pClientName, pSocket, self, self.SELECT_TIMEOUT)
        self.lockClientThreadsUpdate.acquire()
        self.clientRcvThreads[pClientName] = tmpClientRcvThread
        tmpClientRcvThread.start()
        self.lockClientThreadsUpdate.release()
        self.lockServerRequests.acquire()
        self.sentRequests[pClientName] = {}
        self.lockServerRequests.release()
        return True
        
    def pushCommand(self, cmdLines, expectOutput=False, clientName=None):
        retVal = (False, [-1])
        if not type(expectOutput) is bool:
            print "ExpManagerServer: pushCommand(): parameter \"expectOutput\" should be boolean.\n"
            return retVal
        expectOutput = 1 if expectOutput else 0
        if cmdLines is None:
            print "ExpManagerServer: pushCommand(): Empty commands list\n"
            return retVal
        else:
            if type(cmdLines) != list:
                print "ExpManagerServer: pushCommand(): The supplied argument is not a list\n"
                return retVal
            else:
                if len(cmdLines) < 1:
                    print "ExpManagerServer: pushCommand(): Empty commands argument\n"
                    return retVal
                else:
                    for i, val in enumerate(cmdLines):
                        if type(val) != str:
                            print "ExpManagerServer: pushCommand(): The argument " + i + " is not of type string\n"
                            return retVal
                        else:
                            if len(val) < self.MIN_CMD_LEN:
                                print "ExpManagerServer: pushCommand(): The argument " + i + " is too short\n"
                                return retVal
        self.lockServerRequests.acquire()
        SNlist = []
        if clientName is None:
            for k in self.clientRcvThreads.keys(): # only to clients who have connected back to the server
                if (k in self.clientPushThreads) and self.clientPushThreads[k].isAlive():
                    for i, cmd in enumerate(cmdLines):
                        #self.lockServerRequests.acquire()
                        self.currSeqNum = self.currSeqNum + 1
                        self.sentRequests[k][self.currSeqNum] = [cmd, ""]
                        SNlist.append(self.currSeqNum)
                        self.clientPushThreads[k].pushCommand(self.currSeqNum, expectOutput, cmd)
                        #self.lockServerRequests.release()
                    retVal = (True, SNlist)
        else:
            if (clientName in self.clientPushThreads) and (clientName in self.clientRcvThreads): # only if client has connected back to the server
                if self.clientPushThreads[clientName].isAlive():
                    for i, cmd in enumerate(cmdLines):
                        #self.lockServerRequests.acquire()
                        self.currSeqNum = self.currSeqNum + 1
                        self.sentRequests[clientName][self.currSeqNum] = [cmd, ""]
                        SNlist.append(self.currSeqNum)
                        self.clientPushThreads[clientName].pushCommand(self.currSeqNum, expectOutput, cmd)
                        #self.lockServerRequests.release()
                    retVal = (True, SNlist)
        self.lockServerRequests.release()
        return retVal
        
    def saveResponse(self, clientName, response):
        if len(response) < 1:
            return False
        self.lockServerRequests.acquire()
        print "ExpManagerServer: Processing (received from " + clientName + ") message: \n" + response + "\n"
        fields = response.split(self.DELIMITER)
        if len(fields) != 2:
            print "ExpManagerServer: Received a malformed message \n"
            self.lockServerRequests.release()
            return False
        tmpSeqNo = -1
        try:
            tmpSeqNo = int(fields[0])
        except ValueError:
            print "ExpManagerServer: Received a message with bad SEQNUM format \n"
            self.lockServerRequests.release()
            return False
        ((self.sentRequests[clientName][tmpSeqNo])[1]) = fields[1]
        self.lockServerRequests.release()
        return True
    
    def disconnectClient(self, client):
        self.lockClientThreadsUpdate.acquire()
        if client in self.clientPushThreads:
            if (not self.clientPushThreads[client] is None) and self.clientPushThreads[client].isAlive():
                self.clientPushThreads[client].stop()
            del self.clientPushThreads[client]
        if client in self.clientRcvThreads:
            if (not self.clientRcvThreads[client] is None) and self.clientRcvThreads[client].isAlive():
                self.clientRcvThreads[client].stop()
            del self.clientRcvThreads[client]
        self.lockClientThreadsUpdate.release()
        print "ExpManagerServer: Client " + client + " is now disconnected\n"
        return True
    
    def addClientHost(self, pClientName, pClientIP):
        if not self.serverIsRunning:
            print  "ExpManagerServer:addClientHost: Server is not running\n"
            return False
        if (not type(pClientName) is str) or \
            (len(pClientName) < 1) or \
            (not type(pClientIP) is str) or \
            (len(pClientIP) < 7) or \
            not self.myNetHelper.isIPAddr(pClientIP):
            print  "ExpManagerServer:addClientHost: Bad arguments (" + pClientName + "," + pClientIP + ")\n"
            return False
        self.lockClientThreadsUpdate.acquire()
        self.clientAddresses[pClientName] = pClientIP
        self.clientPushThreads[pClientName] = None
        tmpClientPushThread = clientPushThread(pClientName, self)
        self.clientPushThreads[pClientName] = tmpClientPushThread
        tmpClientPushThread.start()
        self.lockClientThreadsUpdate.release()
        return True
    
    def getResponseString(self, pSeqNum):
        if not type(pSeqNum) is int:
            return None
        for tmpReq in self.sentRequests.itervalues():
            if tmpReq.has_key(pSeqNum):
                return tmpReq[pSeqNum][1]
        return None
    
    def saveResponseToFile(self, pSeqNum, pFilename):
        if (not type(pFilename) is str) and len(pFilename) == 0:
            return False
        strResp = self.getResponseString(pSeqNum)
        if strResp is None:
            return False
        try:
            with open(pFilename):
                print "ExpManagerServer: saveResponseToFile: File %s already exists!" % pFilename
                return False
        except IOError:
            print "ExpManagerServer: Good, file does not exist already."
        try:
            f = open(pFilename,'w')
            f.write(strResp)
            f.close()
        except IOError as err:
            print "ExpManagerServer: saveResponseToFile: Failed to write file %s: \n %s \n" % (pFilename, str(err)) 
            os.remove(pFilename)
            
    def stop(self):
        if self.serverIsRunning:
            print "ExpManagerServer: Handling SIGTERM. Shutting down now..."
            for k in self.clientAddresses.keys():
                self.disconnectClient(k)
            self.serverSocketThread.stop()
            self.serverIsRunning = False
            print "ExpManagerServer: STOPPED !!!!!!!!!!\n"
        






class serverSocketThread(Thread):
    def __init__(self, serverObj):
        Thread.__init__(self)
        self.serverObj = serverObj
        self.running = False
    
    def run(self):
        # Create the server socket
        try:
            self.serverObj.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print "serverSocketThread: Binding server socket to " + self.serverObj.HOST_IP + " and port " + str(self.serverObj.serverListeningPort) + "\n"
            self.serverObj.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.serverObj.serverSocket.bind((self.serverObj.HOST_IP, self.serverObj.serverListeningPort))
            self.serverObj.serverSocket.listen(5)
        except socket.error:
            print "serverSocketThread: Server socket init error. Terminating...\n"
            self.serverObj.stop()
            return
        # Expect for Clients to connect
        self.running = True
        while self.running:
            try:
                ready = select.select([self.serverObj.serverSocket], [], [], self.serverObj.SELECT_TIMEOUT)
                if ready[0] and self.running:
                    (tmpSocket, tmpAddress) = self.serverObj.serverSocket.accept()
                    client = None
                    for clientName, ipAddr in self.serverObj.clientAddresses.iteritems():
                        if ipAddr == tmpAddress[0]:
                            client = clientName
                    if not client is None:
                        print "serverSocketThread: Accepted incoming connection from " + client + " (" + tmpAddress[0] + ").\n"
                        if not self.serverObj.createClientReceiveThread(tmpSocket, client):
                            print "serverSocketThread: Failed to create a new thread for incoming connection from " + client + " (" + tmpAddress[0] + ").\n"
                            tmpSocket.shutdown(socket.SHUT_RDWR)
                            tmpSocket.close()
                    else:
                        print "serverSocketThread: Received incoming connection from an unknown address (" + tmpAddress[0] + "). Killing the connection.\n"
                        tmpSocket.shutdown(socket.SHUT_RDWR)
                        tmpSocket.close()
            except (socket.error, Exception):
                print "serverSocketThread: Couldn't accept new connections. Program is exiting...\n"
                self.serverObj.stop()
                return
        print "serverSocketThread: KILLED !!!!!!!!!!\n"
        
    def stop(self):
        if self.running:
            print "serverSocketThread: Stopping the thread loop\n"
            self.running = False
            self.serverObj.serverSocket.shutdown(socket.SHUT_RDWR)
            self.serverObj.serverSocket.close()
        print "serverSocketThread: STOPPED !!!!!!!!!!\n"






class clientPushThread(Thread):
    def __init__(self, clientName, serverObj):
        Thread.__init__(self)
        self.running = False
        self.clientName = clientName
        self.serverObj = serverObj
        self.myConnection = None
        self.myCondVar = Condition()
        self.QUEUE = deque()
        
    def run(self):
        print "clientPushThread:" + self.clientName + ": Starting Client-Push thread loop \n"
        self.running = True
        print "clientPushThread:" + self.clientName + ": Attempting to connect to client \n"
        if not self.__connectToClient():
            self.stop()
            return
        print "clientPushThread:" + self.clientName + ": Connected to client \n"
        while self.running:
            self.__consumeItem()
        print "clientPushThread:" + self.clientName + ": KILLED !!!!!!!!!!\n"
            
    def __connectToClient(self, pConnTimeout=None):
        if (self.clientName is None) or \
            (type(self.clientName) != str) or \
            ((not pConnTimeout is None) and (pConnTimeout < 1)) or \
            (not self.clientName in self.serverObj.clientAddresses):
            return False
        if pConnTimeout is None:
            pConnTimeout = self.serverObj.CONNECT_TIMEOUT
        try:
            # Connect to the Client
            tmpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tmpSocket.bind((self.serverObj.HOST_IP, 0))
            tmpSocket.settimeout(pConnTimeout)
            tmpSocket.connect((self.serverObj.clientAddresses[self.clientName], self.serverObj.clientListeningPort))
            tmpSocket.settimeout(None)
            self.myConnection = tmpSocket
        except socket.timeout:
            #traceback.print_exc(file=sys.stdout)
            print "clientPushThread:" + self.clientName + ": Unable to connect. Connection timeout.\n"
            return False
        except socket.error as err:
            #traceback.print_exc(file=sys.stdout)
            print "clientPushThread:" + self.clientName + ": Socket Error:\n" + str(err) + "\n"
            return False
        return True
    
    def __sendMessage(self, msg):
        retVal = False
        if (not self.myConnection is None) and self.running:
            sent = self.myConnection.send(msg)
            if sent == 0:
                print "clientPushThread:" + self.clientName + ": The client has closed the connection\n"
            else:
                retVal = True
        return retVal
    
    def pushCommand(self, pSeqNum, pExpectOutput, pCmd):
        self.myCondVar.acquire()
        self.QUEUE.append((pSeqNum, str(pExpectOutput), pCmd))
        self.myCondVar.notify()
        self.myCondVar.release()
        
    def __consumeItem(self):
        self.myCondVar.acquire()
        while (not self.__item_is_available()) and self.running:
            self.myCondVar.wait()
        tmpCmd = None
        try:
            tmpCmd = self.QUEUE.popleft()
        except IndexError:
            print "clientPushThread:__consumeItem: Empty item. \n"
        if not tmpCmd is None:
            msgData = str(tmpCmd[0]) + self.serverObj.DELIMITER + tmpCmd[1] + self.serverObj.DELIMITER + tmpCmd[2] + self.serverObj.MESSAGE_SEPARATOR
            if not self.__sendMessage(msgData):
                print "clientPushThread:__consumeItem:" + self.clientName + ": Failed to send the message:\n" + msgData + "\n"
            else:
                print "saveResponseclientPushThread:__consumeItem:" + self.clientName + ": Sent the message:\n" + msgData + "\n"
        self.myCondVar.release()

    def __item_is_available(self):
        return bool(self.QUEUE)
    
    def stop(self):
        if self.running:
            print "clientPushThread:" + self.clientName + ": Stopping Client-Push thread\n"
            self.running = False;
            if not self.myConnection is None:
                self.myConnection.shutdown(socket.SHUT_RDWR)
                self.myConnection.close()
            self.myCondVar.acquire()
            self.myCondVar.notify()
            self.myCondVar.release()
        print "clientPushThread:" + self.clientName + ": STOPPED !!!!!!!!!!\n"
    









                
class clientReceiveThread(Thread):
    
    def __init__(self, clientName, theSocket, serverObj, pTimeout=None):
        Thread.__init__(self)
        self.running = False
        self.clientName = clientName
        self.myConnection = theSocket
        self.timeout = pTimeout
        self.serverObj = serverObj
        self.currentResponse = None
        print "clientReceiveThread:" + self.clientName + ": Thread has been created.\n\n"
        
        
    def run(self):
        print "clientReceiveThread:" + self.clientName + ": Starting Client-RX thread loop\n"
        self.running = True
        while self.running:
            rcvMsg = self.receiveMessage(self.timeout)
            if rcvMsg == "":
                self.serverObj.disconnectClient(self.clientName)
            elif (rcvMsg is None) or (len(rcvMsg) < self.serverObj.MIN_MESSAGE_LEN):
                continue
            else:
                self.storeResponse(rcvMsg)
        print "clientReceiveThread:" + self.clientName + ": KILLED !!!!!!!!!!\n"
                
    def receiveMessage(self, timeout=None):
        message = None
        if (not type(timeout) is int) or (timeout < 0):
            print "clientReceiveThread:" + self.clientName + ": Can't receive using a bad timeout value!\n"
            return message
        try:
            if (timeout is None) or (timeout == 0):
                self.myConnection.setblocking(1)
                message = self.myConnection.recv(self.serverObj.RCVBUFFSIZE)
            else:
                self.myConnection.setblocking(0)
                ready = select.select([self.myConnection], [], [], timeout)
                if ready[0] and self.running:
                    message = self.myConnection.recv(self.serverObj.RCVBUFFSIZE)
        except socket.timeout:
            #traceback.print_exc(file=sys.stdout)
            print "clientReceiveThread:" + self.clientName + ": receiveMessage(): Server thread's socket has timed out. Terminating...\n"
            message = ""
        except socket.error:
            #traceback.print_exc(file=sys.stdout)
            print "clientReceiveThread:" + self.clientName + ": receiveMessage(): Client thread's socket has closed. Terminating...\n"
            message = ""
        return message
    
    def storeResponse(self, pResponse):
        if len(pResponse.strip()) == 0:
            return
        if not self.serverObj.MESSAGE_SEPARATOR in pResponse:
            if self.currentResponse is None:
                self.currentResponse = pResponse
            else:
                self.currentResponse += pResponse
        else:
            responses = pResponse.split(self.serverObj.MESSAGE_SEPARATOR)
            lastItem = responses.pop(-1)
            for tmpResp in responses:
                if len(tmpResp.strip()) > 0:
                    if self.currentResponse is None:
                        self.currentResponse = tmpResp
                    else:
                        self.currentResponse += tmpResp
                    self.serverObj.saveResponse(self.clientName, self.currentResponse)
                    self.currentResponse = None
            if len(lastItem.strip()) > 0:
                self.currentResponse = lastItem
    
    def stop(self):
        if self.running:
            print "clientReceiveThread:" + self.clientName + ": Stopping Client thread\n"
            self.running = False;
            self.myConnection.shutdown(socket.SHUT_RDWR)
            self.myConnection.close() 
        print "clientReceiveThread:" + self.clientName + ": STOPPED !!!!!!!!!!\n"
        



if __name__ == "__main__":
    print 'This is ExpManagerServer module main'
    try:
        theServer = ExpManagerServer()
        signal.signal(signal.SIGTERM, theServer.stop)
        theServer.start()
        time.sleep(2)
        theServer.addClientHost("thesisboost", "192.168.8.1")
        theServer.addClientHost("vaioZ", "192.168.8.2")
        #theServer.addClientHost("cosmic", "192.168.8.1")
        time.sleep(2)
        theServer.pushCommand(["iperf -s -i 1 -y C > iperfServer.txt"], False, "thesisboost")
        time.sleep(1)
        theServer.pushCommand(["iperf -c 192.168.8.1 -t 10"], False, "vaioZ")
        time.sleep(11)
        theServer.pushCommand(["cat iperfServer.txt"], True, "thesisboost")
        time.sleep(1)
        theServer.pushCommand(["killall iperf"])
        theServer.pushCommand(["rm iperfServer.txt"], False, "thesisboost")
        #theServer.pushCommand(["date"], "vaioZ")
        #theServer.pushCommand(["ls -la"], "vaioZ")
        #theServer.pushCommand(["cat /proc/cpuinfo"])
        #for i in range(0, 10):
        #    theServer.pushCommand(["date"], False, "thesisboost")
        while True: time.sleep(1)
    except KeyboardInterrupt:
        theServer.stop()
    
    
