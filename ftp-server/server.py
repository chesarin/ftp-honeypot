#!/usr/bin/env python
import os
import time
from pyftpdlib import ftpserver

class MyFTPHandler(ftpserver.FTPHandler):

    def found_terminator(self):
        r"""Called when the incoming data stream matches the \r\n
        terminator.
        """
        if self._idler is not None and not self._idler.cancelled:
            self._idler.reset()

        line = ''.join(self._in_buffer)
        self._in_buffer = []
        self._in_buffer_len = 0

        cmd = line.split(' ')[0].upper()
        arg = line[len(cmd)+1:]
        kwargs = {}
        if cmd == "SITE" and arg:
            cmd = "SITE %s" % arg.split(' ')[0].upper()
            arg = line[len(cmd)+1:]

        if cmd != 'PASS':
            self.logline("<== %s" % line)
        else:
#            self.logline("<== %s %s" % (line.split(' ')[0], '*' * 6))
            #I want to get the password utilized by attacker
            self.logline("<== %s" % (line))

        # Recognize those commands having a "special semantic". They
        # should be sent by following the RFC-959 procedure of sending
        # Telnet IP/Synch sequence (chr 242 and 255) as OOB data but
        # since many ftp clients don't do it correctly we check the
        # last 4 characters only.
        if not cmd in self.proto_cmds:
            if cmd[-4:] in ('ABOR', 'STAT', 'QUIT'):
                cmd = cmd[-4:]
            else:
                msg = 'Command "%s" not understood.' % cmd
                self.respond('500 ' + msg)
                if cmd:
                    self.log_cmd(cmd, arg, 500, msg)
                return

        if not arg and self.proto_cmds[cmd]['arg'] == True:
            msg = "Syntax error: command needs an argument."
            self.respond("501 " + msg)
            self.log_cmd(cmd, "", 501, msg)
            return
        if arg and self.proto_cmds[cmd]['arg'] == False:
            msg = "Syntax error: command does not accept arguments."
            self.respond("501 " + msg)
            self.log_cmd(cmd, arg, 501, msg)
            return

        if not self.authenticated:
            if self.proto_cmds[cmd]['auth'] or (cmd == 'STAT' and arg):
                msg = "Log in with USER and PASS first."
                self.respond("530 " + msg)
                self.log_cmd(cmd, arg, 530, msg)
            else:
                # call the proper ftp_* method
                self.process_command(cmd, arg)
                return
        else:
            if (cmd == 'STAT') and not arg:
                self.ftp_STAT('')
                return

            # for file-system related commands check whether real path
            # destination is valid
            if self.proto_cmds[cmd]['perm'] and (cmd != 'STOU'):
                if cmd in ('CWD', 'XCWD'):
                    arg = self.fs.ftp2fs(arg or '/')
                elif cmd in ('CDUP', 'XCUP'):
                    arg = self.fs.ftp2fs('..')
                elif cmd == 'LIST':
                    if arg.lower() in ('-a', '-l', '-al', '-la'):
                        arg = self.fs.ftp2fs(self.fs.cwd)
                    else:
                        arg = self.fs.ftp2fs(arg or self.fs.cwd)
                elif cmd == 'STAT':
                    if glob.has_magic(arg):
                        msg = 'Globbing not supported.'
                        self.respond('550 ' + msg)
                        self.log_cmd(cmd, arg, 550, msg)
                        return
                    arg = self.fs.ftp2fs(arg or self.fs.cwd)
                elif cmd == 'SITE CHMOD':
                    if not ' ' in arg:
                        msg = "Syntax error: command needs two arguments."
                        self.respond("501 " + msg)
                        self.log_cmd(cmd, "", 501, msg)
                        return
                    else:
                        mode, arg = arg.split(' ', 1)
                        arg = self.fs.ftp2fs(arg)
                        kwargs = dict(mode=mode)
                else:  # LIST, NLST, MLSD, MLST
                    arg = self.fs.ftp2fs(arg or self.fs.cwd)

                if not self.fs.validpath(arg):
                    line = self.fs.fs2ftp(arg)
                    msg = '"%s" points to a path which is outside ' \
                          "the user's root directory" % line
                    self.respond("550 %s." % msg)
                    self.log_cmd(cmd, arg, 550, msg)
                    return

            # check permission
            perm = self.proto_cmds[cmd]['perm']
            if perm is not None and cmd != 'STOU':
                if not self.authorizer.has_perm(self.username, perm, arg):
                    msg = "Not enough privileges."
                    self.respond("550 " + msg)
                    self.log_cmd(cmd, arg, 550, msg)
                    return

            # call the proper ftp_* method
            self.process_command(cmd, arg, **kwargs)


now = lambda: time.strftime("%Y-%b-%d %H:%M:%S ")
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
#    handler = ftpserver.FTPHandler
    handler = MyFTPHandler
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
