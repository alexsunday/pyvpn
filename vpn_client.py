#!/usr/bin/env python
# encoding: utf-8
'''
Created on 2014年12月6日

@author: Sunday
client:
eth0: 192.168.2.108/24
tun0: 192.168.10.2/24
ioctl a tun device;
set 192.168.0.1/24 to this tun;
connect to heruilong1988.oicp.net 23456
establish connection, large conn with heartbeat,
first, send my ip 192.168.10.2 to server
'''
import fcntl  # @UnresolvedImport
import socket
import select
import os
import logging
import struct
import time
import subprocess
import sys
logger = logging.getLogger('vpn')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


def make_tun():
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = TUNSETIFF + 2
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    # Open TUN device file.
    tun = open('/dev/net/tun', 'r+b')
    # Tall it we want a TUN device named tun0.
    ifr = struct.pack('16sH', 'tun%d', IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    # Optionally, we want it be accessed by the normal user.
    fcntl.ioctl(tun, TUNSETOWNER, 1000)
    return tun


def conn_to_vpn():
    sock = socket.socket()
    addr = ('heruilong1988.oicp.net', 23456)
    try:
        sock.connect(addr)
    except socket.error as e:
        print 'Connect to VPN:[%d],[%s]' % (e.errno, e.strerror)
        return None
    sock.setblocking(False)
    return sock


class Client(object):
    def __init__(self, sock):
        self.sock = sock
        self.buf = ''

    def set_tunfd(self, tunfd):
        self.tunfd = tunfd

    def get_frame(self, buf):
        if len(buf) <= 20:
            return -1
        pack_len = struct.unpack('!H', buf[2:4])[0]
        logger.info('FRAME:[%d], BUF:[%d]' % (pack_len, len(buf)))
        if len(buf) < pack_len:
            return -1
        return pack_len

    def recv(self, buf):
        self.buf += buf
        while True:
            # 一次只能写入一个 IP包，帧。
            length = self.get_frame(self.buf)
            if length == -1:
                break
            frame = self.buf[:length]
            self.buf = self.buf[length:]
            os.write(self.tunfd, frame)
            logger.info('Write to TUN:[%d]' % len(frame))


def main():
    buflen = 65536
    tundev = make_tun()
    tunfd = tundev.fileno()
    logger.info(u'TUN dev OK, FD:[%d]' % tunfd)
    time.sleep(1)
    subprocess.check_call('ifconfig tun0 192.168.10.2/24 up', shell=True)
    subprocess.check_call('route add -net 192.168.0.0/24 gw 192.168.10.1 tun0',
                          shell=True)
    time.sleep(1)

    sock = conn_to_vpn()
    if sock is None:
        print u'SOCK dev Fail'
        sys.exit(-1)
    client = Client(sock)
    client.set_tunfd(tunfd)
    sockfd = sock.fileno()
    logger.info(u'SOCK dev OK, FD:[%d]' % sockfd)

    fds = [tunfd, sockfd, ]
    while True:
        rs, _, _ = select.select(fds, [], [], 0.1)
        for fd in rs:
            if fd == tunfd:
                rcv = os.read(tunfd, buflen)
                if len(rcv) == 0:
                    logger.warn(u'TUN recv [0], Continue')
                    continue
                sent_len = sock.send(rcv)
                logger.info('TUN recv, write to SOCK:[%r]' % sent_len)
            elif fd == sockfd:
                rcv = sock.recv(buflen)
                if len(rcv) == 0:
                    logger.warn(u'SOCK recv [0], break')
                    os.close(sockfd)
                    break
                logger.info('SOCK recv [%d]' % len(rcv))
                client.recv(rcv)


if __name__ == '__main__':
    main()
