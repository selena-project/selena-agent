#!/usr/bin/env python

# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------
#   Copyright (C) 2014 Dimosthenis Pediaditakis.
#
#   Inspired from sample code found here:
#       http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
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


import sys
import os
import time
import atexit
import signal
import fileinput
import abc
import logging
from pyxs import Client, PyXSError
import threading
import subprocess
import pwd

MANAGEMENT_IFACE = 'eth0'
SELENA_AGENT_ERROR_MSG = '>>>>SELENA AGENT ERROR<<<<'
SELENA_XS_LOCK_FREE = 'FREE'
SELENA_XS_LOCK_RESERVED = 'RESERVED'
SELENA_XS_LOCK_DONE = 'DONE'
SELENA_XS_LOCK_DISABLED = 'DISABLED'

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
        if not self.checkPathExists(basedir, script) or not self.is_exe(fullPath):
            if verbose:
                print 'File ' + fullPath + " doesn't exist or is not executable" 
            return (None, None)
        origDir = os.getcwd()
        cmd = ("./" + script + args).strip()
        try:
            os.chdir(basedir)
            process = subprocess.Popen(cmd,
                                       shell=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT,
                                       stdin=subprocess.PIPE)
            if not cmd.endswith('&'):
                (output, status) = (process.communicate()[0], process.returncode)
            else:
                if process.poll() is None:
                    # process is still running
                    self.addProcess(process)
                    (output, status) = ('', 0)
                else:
                    # process has finished very fast, output is already available
                    (output, status) = (process.communicate()[0], process.returncode)
        except OSError, exc:
            if verbose:
                print 'Unable to run command: %s: \n %s' % (cmd, exc.strerror)
            return (None, None)
        finally:
            os.chdir(origDir)
        return (status, output)
    
    def runCommand(self, pCommand, pScript=False, verbose=False):
        if (pCommand is None) or \
                (not isinstance(pCommand, str) and not isinstance(pCommand, unicode)) or \
                (len(pCommand) < 2):
            if verbose:
                print "Bad command: \n" + pCommand + "\n"
            return (None, None)
        origDir = os.getcwd()
        try:
            if pScript:
                process = subprocess.Popen(pCommand.strip(),
                                           shell=True,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           stdin=subprocess.PIPE)
            else:
                process = subprocess.Popen(pCommand.strip().split(),
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           stdin=subprocess.PIPE)
            if not pCommand.strip().endswith('&'):
                self.addProcess(process)
                (output, status) = (process.communicate()[0], process.returncode)
                self.removeProcess(process)
            else:
                if process.poll() is None:
                    # process is still running
                    self.addProcess(process)
                    (output, status) = ('', 0)
                else:
                    # process has finished very fast, output is already available
                    (output, status) = (process.communicate()[0], process.returncode)
        except OSError, exc:
            if verbose:
                print 'Unable to run command: %s: \n %s' % (pCommand, exc.strerror)
            return (None, None)
        finally:
            os.chdir(origDir)
        return (status, output)

    def killAllProcesses(self):
        self.lock.acquire()
        for process in self.runningProcesses:
            if process.poll() is None:
                process.kill()
        del self.runningProcesses[:]
        self.lock.release()

    def writeDebugFile(self, pFile, pMessage):
        try:
            with open(pFile,  'a') as pf:
                pf.write(pMessage + "\n")
        except IOError:
            print 'Error writting'

    def addProcess(self, pProcess):
        self.lock.acquire()
        if not (pProcess in self.runningProcesses):
            self.runningProcesses.append(pProcess)
        self.lock.release()
        self.garbageCollectFinished()

    def removeProcess(self, pProcess):
        self.lock.acquire()
        if pProcess in self.runningProcesses:
            self.runningProcesses.remove(pProcess)
        self.lock.release()

    def garbageCollectFinished(self):
        self.lock.acquire()
        for process in self.runningProcesses:
            if process.poll() is not None:
                # process has finished
                self.runningProcesses.remove(process)
        self.lock.release()

    def getProcessesStr(self):
        return str(self.runningProcesses)



EXEC = CommandTools()


class Daemon:
    __metaclass__ = abc.ABCMeta

    def __init__(self, pidfile):
        self.pidfile = pidfile

    def daemonize(self):
        """Deamonize class. UNIX double fork mechanism."""
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as err:
            sys.stderr.write('fork #1 failed: {0}\n'.format(err))
            sys.exit(1)

        # decouple from parent environment
        os.chdir('/')
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as err:
            sys.stderr.write('fork #2 failed: {0}\n'.format(err))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)

        pid = str(os.getpid())
        with open(self.pidfile,'w+') as f:
            f.write(pid + '\n')

    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        """Start the daemon."""
        # Check for a pidfile to see if the daemon already runs
        try:
            with open(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
        except (IOError, TypeError) as e:
            pid = None

        if pid:
            message = "pidfile {0} already exist. " + \
                    "Daemon already running?\n"
            sys.stderr.write(message.format(self.pidfile))
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        """Stop the daemon."""

        # Get the pid from the pidfile
        try:
            with open(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
        except (IOError, TypeError) as e:
            pid = None

        if not pid:
            message = "pidfile {0} does not exist. " + "Daemon not running?\n"
            sys.stderr.write(message.format(self.pidfile))
            return # not an error in a restart

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.05)
        except OSError as err:
            e = str(err.args)
            if e.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print (str(err.args))
                sys.exit(1)

    def status(self):
        """Return the status of the service"""
        try:
            with open(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
        except (IOError, TypeError) as e:
            pid = None
        if not pid:
            sys.stderr.write("selena-agent service stop/waiting \n")
            return False
        try:
            with open("/proc/%d/status" % pid, 'r'):
                sys.stderr.write("selena-agent service start/running \n (PID is %d)\n" % pid)
                return True
        except IOError as e:
            sys.stderr.write("selena-agent service stop/waiting \n")
        return False


    def restart(self):
        """Restart the daemon."""
        self.stop()
        self.start()

    @abc.abstractmethod
    def run(self):
        """You should override this method when you subclass Daemon.

        It will be called after the process has been daemonized by
        start() or restart()."""

    @abc.abstractmethod
    def stopGracefully(self, signum, frame):
        """You should override this method when you subclass Daemon.

        It will be called before the daemonized process is killed via stop()."""



class SelenaAgentDaemon(Daemon):

    def __init__(self, pidfile, logfile, logLevel):
        '''
        Constructor
        '''
        super(SelenaAgentDaemon, self).__init__(pidfile)
        # Configure the logger
        self.logger = logging.getLogger('selena-agent')
        fhandler = logging.FileHandler(logfile)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        fhandler.setFormatter(formatter)
        self.logger.addHandler(fhandler)
        self.logger.setLevel(logLevel)

    def checkCmdExitStatus(self, pStatus, pMessage):
        if pStatus != 0: # this includes error exit codes and -1
            self.logger.critical("Stopping the agent.\nError:%s", pMessage)
            self.stop()

    def sanitiseValueForXS(self, pValue):
        if not isinstance(pValue, str) or isinstance(pValue, unicode):
            return None
        retVal = ''
        for c in pValue:
            if c >= ' ' and c <= '~' and c != '\\':
                retVal += c
            else:
                retVal += '\\'
                if c == '\t':
                    retVal += 't'
                elif c == '\n':
                    retVal += 'n'
                elif c == '\r':
                    retVal += 'r'
                elif c == '\\':
                    retVal += '\\'
                else:
                    if ord(c) < 010:
                        retVal += "%03o" % ord(c)
                    else:
                        retVal += "x%02x" % ord(c)
        return retVal

    def unsanitiseValueFromXS(self, pValue):
        if not isinstance(pValue, str) or isinstance(pValue, unicode):
            return None
        retVal = ''
        i = 0
        while i < len(pValue):
            if pValue[i] == '\\':
                i += 1
                if pValue[i] == '\\':
                    retVal += '\\'
                elif pValue[i] == 't':
                    retVal += '\t'
                elif pValue[i] == 'n':
                    retVal += '\n'
                elif pValue[i] == 'r':
                    retVal += '\r'
                elif pValue[i] == 'x':
                    retVal += chr(int(pValue[i+1:i+3], 16))
                    i += 2
                elif pValue[i] == '0' or \
                     pValue[i] == '1' or \
                     pValue[i] == '2' or \
                     pValue[i] == '3' or \
                     pValue[i] == '4' or \
                     pValue[i] == '5' or \
                     pValue[i] == '6' or \
                     pValue[i] == '7':
                    retVal += chr(int(pValue[i:i+3], 8))
                    i += 2
            else:
                retVal += pValue[i]
            i += 1
        return retVal

    def readXSvalue(self, pPath):
        tmpValue = None
        try:
            tmpValue = self.xsClient.read(pPath)
        except PyXSError as e:
            self.logger.error("Error reading the '%s' key from XenStore: \n%s", pPath, str(e))
        tmpValue = self.unsanitiseValueFromXS(str(tmpValue))
        self.logger.debug("readXSvalue path=%s value=%s", pPath, tmpValue)
        return tmpValue

    def writeXSvalue(self, pPath, pValue):
        self.logger.debug("writeXSvalue path=%s value=%s", pPath, pValue)
        try:
            self.xsClient.write(pPath, self.sanitiseValueForXS(str(pValue).strip()))
        except PyXSError as e:
            self.logger.error("Error writing value '%s' on the '%s' path in XenStore: \n%s", pValue, pPath, str(e))
            return False
        return True

    def run(self):
        # # Initialize the Xenstore class memebers
        self.stopXS = False
        try:
            self.xsClient = Client(xen_bus_path="/proc/xen/xenbus")
        except PyXSError as e:
            self.logger.error("Error creating the XenStore client instance: \n%s", str(e))
        # Handle the SIGTERM signal gracefully
        signal.signal(signal.SIGTERM, self.stopGracefully)
        self.logger.info("Starting the Selena agent ")
        # Check if Selena XS path is created (from Domain-0)
        if self.readXSvalue('Selena') is None:
            self.logger.error("Failed to read path 'Selena' on Xenstore")
            self.stop()
        # Check that the Selena/cmd path exists and is readable
        if self.readXSvalue('Selena/cmd') is None:
            self.logger.error("Failed to read path 'Selena/cmd' on Xenstore")
            self.stop()
        # Read the management IP address
        tmpVal = self.readXSvalue('Selena/bootipaddr')
        if tmpVal is None:
            self.logger.error("Failed to read path 'Selena/bootipaddr' on Xenstore")
            self.stop()
        mgmtIpAddr = tmpVal.strip()
        # Read the management netmask
        tmpVal = self.readXSvalue('Selena/bootipmask')
        if tmpVal is None:
            self.logger.error("Failed to read path 'Selena/bootipmask' on Xenstore")
            self.stop()
        mgmtNetmask = tmpVal.strip()
        # Configure the management interface
        (status, out) = EXEC.runCommand('/sbin/ifconfig ' + MANAGEMENT_IFACE + ' ' + mgmtIpAddr + ' netmask ' + mgmtNetmask)
        self.checkCmdExitStatus(status, "Could not configure the management interface: \n" + 'ifconfig ' + MANAGEMENT_IFACE + ' ' + mgmtIpAddr + ' netmask ' + mgmtNetmask)
        # Free the lock
        if not self.writeXSvalue('Selena/lock', SELENA_XS_LOCK_FREE):
            self.logger.error("Failed to free the lock (path 'Selena/lock' on Xenstore)")
            self.stop()
        #---------------------------------------------------
        # Here goes the main loop of the selena agent daemon
        #---------------------------------------------------
        while not self.stopXS:
            # Wait for the new command to arrive
            (status, _) = EXEC.runCommand('/usr/sbin/xenstore-watch -n 2 Selena/cmd')
            if status is None or status != 0:
                if not self.stopXS:
                    self.logger.error("Failed to watch the Selena/cmd Xenstore path")
                rcvCmd = None
            else:
                rcvCmd = self.readXSvalue('Selena/cmd')
            if (rcvCmd is not None) and len(rcvCmd) > 1:
                self.logger.debug("Received command '%s' via XenStore", rcvCmd)
                # Execute the received command
                (status, output) = EXEC.runCommand(rcvCmd, True)
                if status is None:
                    # The agent has failed to execute the command it received
                    self.logger.error("Failed to execute command: %s", rcvCmd)
                    if not self.writeXSvalue('Selena/response', SELENA_AGENT_ERROR_MSG):
                        self.logger.error("Failed to write to XenStore: Path=%s, Value=%s", 'Selena/response', SELENA_AGENT_ERROR_MSG)
                else:
                    # Write back the output of the executed command
                    # trim output to Xenstore's maximum allowed value length
                    if len(output) > 4090:
                        output = output[:4089]
                    if not self.writeXSvalue('Selena/response', output):
                        self.logger.error("Failed to write to XenStore: Path=%s, Value=%s", 'Selena/response', output)
                    self.logger.debug("Command executed and responded successfully: '%s'", output)
            else:
                if not self.stopXS:
                    self.logger.error("Failed to read the command sent from Selena")
            # Mark the lock as free
            if not self.writeXSvalue('Selena/lock', SELENA_XS_LOCK_DONE):
                self.logger.error("Failed to release the lock (path 'Selena/lock' on Xenstore)")
                self.stop()

    def stopGracefully(self, signum, frame):
        self.stopXS = True
        EXEC.killAllProcesses()
        if self.xsClient:
            self.writeXSvalue('Selena/lock', SELENA_XS_LOCK_DISABLED)
            # Stop the main client
            if self.xsClient.tx_id:
                self.xsClient.transaction_end(commit=True)
            self.xsClient.connection.disconnect()
        self.logger.info("The selena agent has been stopped")
        sys.exit()


if __name__ == "__main__":
    selenaDaemon = SelenaAgentDaemon("/tmp/daemon-selena.pid", "/var/log/selena-agent.log", logging.INFO)
    signal.signal(signal.SIGTERM, selenaDaemon.stopGracefully)
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            selenaDaemon.start()
        elif 'stop' == sys.argv[1]:
            selenaDaemon.stop()
        elif 'restart' == sys.argv[1]:
            selenaDaemon.restart()
        elif 'status' == sys.argv[1]:
            selenaDaemon.status()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart|status" % sys.argv[0]
        sys.exit(2)
