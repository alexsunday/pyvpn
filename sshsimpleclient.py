#!/usr/bin/env python

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

from twisted.conch.ssh import transport, userauth, connection
from twisted.internet import defer, protocol, reactor
import getpass

HOST = '192.168.2.108'
USER = 'sunday'
PWD = '1234567'


class SimpleTransport(transport.SSHClientTransport):
    def verifyHostKey(self, hostKey, fingerprint):
        return defer.succeed(1)

    def connectionSecure(self):
        self.requestService(SimpleUserAuth(USER, SimpleConnection()))


class SimpleUserAuth(userauth.SSHUserAuthClient):
    def getPassword(self):
        return defer.succeed(getpass.getpass(">"))


class SimpleConnection(connection.SSHConnection):
    def serviceStarted(self):
        print 'All OK'
        reactor.stop()  # @UndefinedVariable


protocol.ClientCreator(reactor, SimpleTransport).connectTCP(HOST, 22)
reactor.run()  # @UndefinedVariable
