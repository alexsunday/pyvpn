#!/usr/bin/env python
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
from twisted.internet.protocol import Factory
from src.util import is_valid_netmask, is_valid_ip, inet_atol
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

    def get_free_addr(self):
        while True:
            addr = self._netaddr + 1
            if addr == self._gwaddr:
                continue
            if addr >= self._boardcast:
                return None
            return addr

    def ifconfig(self, gwaddr, netmask):
        assert is_valid_ip(gwaddr)
        assert is_valid_netmask(netmask)
        self.gwaddr = gwaddr
        self.netmask = netmask
        self._netaddr = util.addr_netaddr(self.gwaddr, self.netmask)
        self._boardcast = util.addr_boardcast(self.gwaddr, self.netmask)
        self._gwaddr = inet_atol(self.gwaddr)
        # 已分配地址，整形地址
        self.allocated_addr = []
        util.ifconfig(self.dev, gwaddr, netmask)

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


class VPNProtocol(protocol.Protocol, TimeoutMixin):
    def __init__(self, tundev):
        self.tundev = tundev

    def connectionMade(self):
        self._is_authed = False
        self._is_gzip = True
        self._is_encrypt = False
        self._interval = 120
        self._client_addr = None
        self._client_mask = None
        self._flow_count = 0
        self.buf = ''
        self._user = ''
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

    def user_auth(self, pack):
        user_len = struct.unpack('@b', pack[3])[0]
        assert user_len
        user = pack[4: 4 + user_len]
        pwd_len = struct.unpack('@b', pack[4 + user_len])[0]
        assert pwd_len
        pwd = pack[4 + user_len + 1:]
        assert user and pwd
        retpack = struct.pack('@Hbb', 4, 0, 0)
        self.transport.write(retpack)
        self._is_authed = True
        self._user = user
        return True

    def heartbeat(self):
        assert self._is_authed
        retpack = struct.pack('@Hb', 3, 1)
        self.transport.write(retpack)

    def peer_ifconfig(self):
        assert self._is_authed

    def trans_data(self):
        assert self._is_authed

    def dataReceived(self, data):
        self.setTimeout(None)
        self.buf += data
        self._flow_count += len(data)
        while True:
            pack = self.getpackage()
            if not pack:
                break
            pack_type = struct.unpack('@b', pack[2])[0]
            if pack_type == util.PackageType.AUTH:
                self.user_auth(pack)
            elif pack_type == util.PackageType.HEARTBEAT:
                self.heartbeat()
            elif pack_type == util.PackageType.IFCONFIG:
                self.peer_ifconfig()
            elif pack_type == util.PackageType.DATA:
                self.trans_data()


def main():
    tunprotocol = TunProtocol()
    tundesc = TunDevice(tunprotocol, reactor)
    tundesc.ifconfig('192.168.10.3', '255.255.255.0')
    tundesc.startReading()
    vpnprotocol = VPNProtocol()
    serverfactory = Factory()
    serverfactory.protocol = vpnprotocol
    reactor.listenTCP(1234, serverfactory)  # @UndefinedVariable
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