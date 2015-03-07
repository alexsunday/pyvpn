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
from twisted.protocols.policies import TimeoutMixin
import struct
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


class PackageType(object):
    AUTH = 0
    HEARTBEAT = 1
    IFCONFIG = 2


class VPNProtocol(protocol.Protocol, TimeoutMixin):
    def connectionMade(self):
        self._is_authed = False
        self._is_gzip = True
        self._is_encrypt = False
        self._interval = 120
        self._client_addr = None
        self._client_mask = None
        self._flow_count = 0
        self.buf = ''
        self.setTimeout(self._interval)

    def connectionLost(self, reason):
        self.setTimeout(None)

    def getpackage(self):
        if len(self.buf) <= 2:
            return None
        d_length = struct.unpack('@H', self.buf[:2])[0]
        if len(self.buf) < d_length:
            return None
        pack = self.buf[:d_length]
        self.buf = self.buf[d_length:]
        return pack

    def user_auth(self, user, pwd):
        pass

    def dataReceived(self, data):
        self.setTimeout(None)
        self.buf += data
        self._flow_count += len(data)
        while True:
            pack = self.getpackage()
            if not pack:
                break
            pack_type = struct.unpack('@b', pack[2])[0]
            if pack_type == PackageType.AUTH:
                user_len = struct.unpack('@b', pack[3])[0]
                assert user_len
                user = pack[4: 4 + user_len]
                pwd_len = struct.unpack('@b', pack[4 + user_len])[0]
                assert pwd_len
                pwd = pack[4 + user_len + 1:]
                self.user_auth(user, pwd)
            elif pack_type == PackageType.HEARTBEAT:
                pass


def main():
    tundesc = TunDevice(TunProtocol(), reactor)
    tundesc.ifconfig('192.168.10.3', '255.255.255.0')
    tundesc.startReading()
    reactor.run()  # @UndefinedVariable


if __name__ == '__main__':
    main()


# TODO:
r"""
1, VPN
1.1, 自动的IP配置
2, Win32 client
2.1， Android client
3, 简单的认证机制，地址端口用户名密码
4, 压缩与可选的加密机制
5, 流量控制
6, 限速
7, Web控制与状态显示
LAST, 性能
"""