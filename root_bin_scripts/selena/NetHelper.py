'''
Created on 14 Jul 2013

@author: dimos
'''

import os
import socket, struct
import CommandTools
import sys

class NetHelper(object):
    '''
    classdocs
    
    '''
    EXEC = None

    def __init__(self):
        '''
        Constructor
        '''
        self.EXEC = CommandTools.CommandTools()
    
    def get_default_gateway_linux(self):
        ''' 
        Read the default gateway directly from /proc.
        '''
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

    def isIPAddr(self, host):
        try:
            socket.inet_aton(host)
            return True
        except socket.error:
            return False
        
    def isReachable(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port)) 
        except socket.error:
            return False
        sock.close()
        return True
    
    def getAllNonLocalIPs(self):
        retVal = None
        (retStatus, outputStr) = self.EXEC.runCommand("/sbin/ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print $1}'")
        if retStatus == 0:
           retVal = outputStr.split("\n")
        return retVal
    
    def getFirstNonLocalIP(self):
        return self.getAllNonLocalIPs()[0]
    
if __name__ == "__main__":
    print 'This is NetHelper module main'
    myNetHelper = NetHelper()
    print myNetHelper.get_default_gateway_linux()
    #print myNetHelper.isReachable("192.168.8.1", 22)
    print myNetHelper.getFirstNonLocalIP()
    print socket.gethostname()
    