# encoding: utf-8
'''
Created on 2015年3月7日

@author: Sunday
'''
from twisted.internet.abstract import FileDescriptor
from twisted.internet import fdesc, protocol, reactor
import os
import logging

import util
logger = logging.getLogger("pyvpn")


class TunDevice(FileDescriptor, object):
    def __init__(self, protocol, reactor=None):
        FileDescriptor.__init__(self, reactor=reactor)
        self.dev, _tun = util.make_tun()
        self.tun = _tun.fileno()
        fdesc.setNonBlocking(self.tun)
        self.protocol = protocol
        self.protocol.dev, self.protocol.tun = self.dev, self.tun
        self.protocol.connectionMade()

    def ifconfig(self, ipaddr, netmask):
        util.ifconfig(self.dev, ipaddr, netmask)

    def fileno(self):
        return self.tun

    def _doRead(self, in_):
        self.protocol.dataReceived(in_)

    def doRead(self):
        print '~~~~~~~~~~~~~~~~~~~~~~~~~'
        fdesc.readFromFD(self.tun, self._doRead)
        print '~~~~~~~~~~~~~~~~~~~~~~~~~'

    def writeSomeData(self, data):
        fdesc.writeToFD(self.tun, data)

    def connectionLost(self, reason):
        if self.tun >= 0:
            try:
                os.close(self.tun)
            except OSError as _:
                logger.error("cannot close tunfd")
        FileDescriptor.connectionLost(self, reason)


class TunProtocol(protocol.Protocol):
    def connectionMade(self):
        logger.info('Allocated TUN dev:', self.dev)

    def connectionLost(self, reason):
        pass

    def dataReceived(self, data):
        pass


class VPNProtocol(protocol.Protocol):
    def connectionMade(self):
        pass

    def connectionLost(self, reason):
        pass

    def dataReceived(self, data):
        pass


def main():
    tundesc = TunDevice(TunProtocol(), reactor)
    tundesc.ifconfig('192.168.10.3', '255.255.255.0')
    tundesc.startReading()
    reactor.run()  # @UndefinedVariable


if __name__ == '__main__':
    main()
