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
from util import is_valid_netmask, is_valid_ip, inet_atol
import zlib

logger = logging.getLogger("pyvpn")


class AppException(Exception):
    pass


class TundevException(AppException):
    pass


class IpFullException(TundevException):
    pass


class TunDevice(FileDescriptor, object):
    def __init__(self, protocol, reactor=None):
        FileDescriptor.__init__(self, reactor=reactor)
        self.dev, self._tun = util.make_tun()
        self.tunfd = self._tun.fileno()
        fdesc.setNonBlocking(self.tunfd)
        self.protocol = protocol
        self.protocol.dev, self.protocol.tun = self.dev, self.tunfd
        self.protocol.connectionMade()
        self._write_buf = ''

    def get_free_addr(self):
        addr = self._netaddr
        while True:
            addr = addr + 1
            if addr == self._gwaddr:
                continue
            if addr in self.allocated_addr:
                continue
            if addr >= self._boardcast:
                raise IpFullException("IP分配已满")
            self.allocated_addr.append(addr)
            return addr, inet_atol(self.netmask)

    def remove_addr(self, addr):
        self.allocated_addr.remove(addr)

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
        return self.tunfd

    def _doRead(self, in_):
        self.protocol.dataReceived(in_)

    def doRead(self):
        print '~~~~~~~~~~~~~~~~~~~~~~~~~'
        fdesc.readFromFD(self.tunfd, self._doRead)
        print '~~~~~~~~~~~~~~~~~~~~~~~~~'

    @staticmethod
    def get_frame(buf):
        if len(buf) <= 20:
            return -1
        pack_len = struct.unpack('!H', buf[2:4])[0]
        logger.info('FRAME:[%d], BUF:[%d]' % (pack_len, len(buf)))
        if len(buf) < pack_len:
            return -1
        return pack_len

    def writeSomeData(self, data):
        self._write_buf += data
        while True:
            length = self.get_frame(self._write_buf)
            if length == -1:
                break
            frame = self._write_buf[:length]
            self._write_buf = self._write_buf[length:]
            fdesc.writeToFD(self.tunfd, frame)

    def connectionLost(self, reason):
        if self.tunfd >= 0:
            try:
                os.close(self.tunfd)
            except OSError as _:
                logger.error("cannot close tunfd")
        FileDescriptor.connectionLost(self, reason)


class TunProtocol(protocol.Protocol):
    def connectionMade(self):
        logger.info('Allocated TUN dev:', self.dev)

    def connectionLost(self, reason):
        pass

    def dataReceived(self, data):
        '''
        @summary: 操作系统发给虚拟网卡的数据包，拆出其目标地址，发给目标用户
        //先群发。
        :param data:
        '''


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
        self._user = ''
        self._addr, self._netmask = None, None
        self.setTimeout(self._interval)

    def connectionLost(self, reason):
        '''
        @summary: 释放超时信号，释放已分配IP，写入流量等数据
        :param reason:
        '''
        self.setTimeout(None)
        if self._addr:
            self.tundev.remove_addr(self._addr)

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
        self._addr, self._netmask = self.tundev.get_free_addr()
        # 返回类型2， ip与掩码各4字节，总长度11字节
        retpack = struct.pack('@HbII', 11, 2, self._addr, self._netmask)
        self.transport.write(retpack)

    def trans_data(self, pack):
        assert self._is_authed
        raw_data = zlib.decompress(pack[3:])
        self.tundev.writeSomeData(raw_data)

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
                self.trans_data(pack)


class VPNFactory(Factory):
    def __init__(self, tundev):
        self.protocol = VPNProtocol
        self.tundev = tundev

    def buildProtocol(self, addr):
        p = self.protocol()
        p.factory = self
        p.tundev = self.tundev
        return p


def main():
    # TUN dev
    tunprotocol = TunProtocol()
    tundev = TunDevice(tunprotocol, reactor)
    tundev.ifconfig('192.168.10.3', '255.255.255.240')
    tundev.startReading()
    # tcp for client
    serverfactory = VPNFactory(tundev)
    reactor.listenTCP(1234, serverfactory)  # @UndefinedVariable
    # web console
    # run
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