#!/usr/bin/env python

'''
Created on 13 Jun 2013

@author: dimos
'''

import os
import sys
import threading
import subprocess
import pwd


class CommandTools(object):
    '''
    classdocs
    '''
    
    path = ''
    rootDir = ''
    user = ''
    runningProcesses = []
    lock = None


    def __init__(self, 
                 path=os.environ['PATH'], 
                 rootDir='',#os.environ['HOME'],
                 user=''): #os.environ['USER']):
        '''
        Constructor
        '''
        self.path = path
        self.rootDir = rootDir
        #try:
        #    userRecord = pwd.getpwnam(user)
        #except KeyError, err:
        #    print 'User could not be found'
        #    sys.exit(1)
        self.user = user
        self.lock = threading.RLock()
        
        
    def giveExecRights(self, rootDir, mfile, verbose=False):
        fullPath = os.path.join(rootDir, mfile)
        if(not os.path.exists(fullPath) or os.path.isdir(fullPath)):
            return False
        cmd = 'chmod u+x ' + fullPath
        if verbose:
            print cmd
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        process.wait()
        status = process.returncode
        if verbose:
            print 'Return status: ' + str(status)
        if status is not 0:
            return False
        return True
    
    
    def checkPathExists(self, rootDir, mfile=''):
        fullPath = os.path.join(rootDir, mfile)
        return os.path.exists(fullPath)
    
    
    def is_exe(self, fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)
            
        
    def runScript(self, basedir, script, args='', verbose=False):
        fullPath = os.path.join(basedir, script)
        if ( (not self.checkPathExists(basedir, script)) or (not self.is_exe(fullPath))):
            if verbose:
                print 'File ' + fullPath + " doesn't exist or is not executable" 
            return False  
        status = 0
        output = ''
        origDir = os.getcwd()
        cmd = "./" + script + args 
    
        try:
            os.chdir(basedir)
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.lock.acquire()
            self.runningProcesses.append(process)
            self.lock.release()
	    if not cmd.strip().endswith('&'): 
            	process.wait()
            	output = process.communicate()[0]
            	status = process.returncode
            self.lock.acquire()
            self.runningProcesses.remove(process)
            self.lock.release()
        except OSError, exc:
            if verbose:
                print 'Unable to run test ' + fullPath
                print exc.strerror
            return (1, '')
        finally:
            os.chdir(origDir)
            
        if status is not 0 and verbose:
            print cmd + ' exited with value ' + str(status)
            
        return (status, output)
    
    def runCommand(self, pCommand):
        if (pCommand is None) or (type(pCommand) != str) or (len(pCommand) < 2):
            print "Bad command: \n" + pCommand + "\n"
            return None
        status = 0
        output = ''
        origDir = os.getcwd()
        try:
            process = subprocess.Popen(pCommand, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self.lock.acquire()
            self.runningProcesses.append(process)
            self.lock.release()
	    if not pCommand.strip().endswith('&'): 
            	process.wait()
            	output = process.communicate()[0]
            	status = process.returncode
            self.lock.acquire()
            self.runningProcesses.remove(process)
            self.lock.release()
        except OSError, exc:
            print 'Unable to run command: ' + pCommand
            print exc.strerror
            return None
        finally:
            os.chdir(origDir)
        if status is not 0:
            print 'Command exited with value ' + str(status)
            
        return (status, output)
    
    def stopAllProcesses(self):
        self.lock.acquire()
        for i, val in enumerate(self.runningProcesses):
            self.runningProcesses[i].terminate()
        self.lock.release()  


if __name__ == "__main__":
    print 'hello'
    myC = CommandTools()
    (s,o) = myC.runCommand(sys.argv[1])
    print 'Status: ' + str(s)
    print 'Output: ' + str(o)
    

        
        
