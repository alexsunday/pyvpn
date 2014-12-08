#!/usr/bin/env python

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

from twisted.conch.ssh import transport, userauth, connection, common, keys, channel
from twisted.internet import defer, protocol, reactor
from twisted.python import log
import struct, sys, getpass, os

USER = 'sunday'  # replace this with a valid username
HOST = '192.168.2.108' # and a valid host

class SimpleTransport(transport.SSHClientTransport):
    def verifyHostKey(self, hostKey, fingerprint):
        print 'host key fingerprint: %s' % fingerprint
        return defer.succeed(1) 

    def connectionSecure(self):
        self.requestService(
            SimpleUserAuth(USER,
                SimpleConnection()))

class SimpleUserAuth(userauth.SSHUserAuthClient):
    def getPassword(self):
        return defer.succeed(getpass.getpass("%s@%s's password: " % (USER, HOST)))

    def getGenericAnswers(self, name, instruction, questions):
        print name
        print instruction
        answers = []
        for prompt, echo in questions:
            if echo:
                answer = raw_input(prompt)
            else:
                answer = getpass.getpass(prompt)
            answers.append(answer)
        return defer.succeed(answers)

class SimpleConnection(connection.SSHConnection):
    def serviceStarted(self):
        print 'All OK'
#         self.openChannel(TrueChannel(2**16, 2**15, self))
#         self.openChannel(FalseChannel(2**16, 2**15, self))
#         self.openChannel(CatChannel(2**16, 2**15, self))

protocol.ClientCreator(reactor, SimpleTransport).connectTCP(HOST, 22)
reactor.run()
