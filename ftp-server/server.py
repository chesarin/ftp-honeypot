#!/usr/bin/env python
import os
import time
from pyftpdlib import ftpserver

now = lambda: time.strftime("[%Y-%b-%d %H:%M:%S]")
f1 = open('ftpd.log', 'a')
f2 = open('ftpd.lines.log', 'a')

def standard_logger(msg):
    f1.write("%s %s\n" %(now(), msg))
    f1.flush()

def line_logger(msg):
    f2.write("%s %s\n" %(now(), msg))
    f2.flush()

def main():
    ftpserver.log = standard_logger
    ftpserver.logline = line_logger
    # Instantiate a dummy authorizer for managing 'virtual' users
    authorizer = ftpserver.DummyAuthorizer()

    # Define a new user having full r/w permissions and a read-only
    # anonymous user
    authorizer.add_user('user', password="12345", homedir='.', perm='elradfmw')
    authorizer.add_anonymous(homedir='.')

    # Instantiate FTP handler class
    handler = ftpserver.FTPHandler
    handler.authorizer = authorizer

    # Define a customized banner (string returned when client connects)
    handler.banner = "pyftpdlib %s based ftpd ready." %ftpserver.__ver__

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
