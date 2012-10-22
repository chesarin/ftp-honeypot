#!/usr/bin/env python
import os
import time
from pyftpdlib import ftpserver

now = lambda: time.strftime("[%Y-%b-%d %H:%M:%S]")
flog = open('ftpd.log', 'a')
clog = open('commands-ftpd.log', 'a')
elog = open('errors-ftpd.log','a')
software_name = 'pure-ftp'
software_version = '1.0.22'

def ftpd_logger(msg):
    flog.write("%s %s\n" %(now(), msg))
    flog.flush()

def command_logger(msg):
    clog.write("%s %s\n" %(now(), msg))
    clog.flush()

def error_logger(msg):
    elog.write("%s %s\n" %(now(), msg))
    elog.flush()
    
def main():
    ftpserver.log = ftpd_logger
    ftpserver.logline = command_logger
    ftpserver.logerror = error_logger
    # Instantiate a dummy authorizer for managing 'virtual' users
    authorizer = ftpserver.DummyAuthorizer()

    # Define a new user having full r/w permissions and a read-only
    # anonymous user
    authorizer.add_user('test', password="12345", homedir='.', perm='elradfmw')
    authorizer.add_anonymous(homedir='.')

    # Instantiate FTP handler class
    handler = ftpserver.FTPHandler
    handler.authorizer = authorizer

    # Define a customized banner (string returned when client connects)
    handler.banner = "%s %s ready." %(software_name, software_version)

    # Specify a masquerade address and the range of ports to use for
    # passive connections.  Decomment in case you're behind a NAT.
    #handler.masquerade_address = '151.25.42.11'
    #handler.passive_ports = range(60000, 65535)

    # Instantiate FTP server class and listen to 0.0.0.0:21
    address = ('127.0.0.1', 21)
    server = ftpserver.FTPServer(address, handler)

    # set a limit for connections
    server.max_cons = 256
    server.max_cons_per_ip = 5

    # start ftp server
    server.serve_forever()

if __name__ == '__main__':
    main()
