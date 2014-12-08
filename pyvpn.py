#!/usr/bin/env python
# encoding: utf-8
import os
import time
import socket
import select
import logging
import struct
import subprocess
import fcntl  # @UnresolvedImport
import sys
logger = logging.getLogger('vpn')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


def make_tun():
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    tun = open('/dev/net/tun', 'r+b')
    ifr = struct.pack('16sH', 'tun%d', IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun


def client():
    tundev = make_tun()
    tunfd = tundev.fileno()
    logger.info(u'TUN dev OK')
    time.sleep(1)
    subprocess.check_call('ifconfig tun0 192.168.10.2/24 up', shell=True)
    subprocess.check_call('route add -net 192.168.0.1/24 gw 192.168.10.1 tun0',
                          shell=True)
    time.sleep(1)

    sock = socket.socket()
    addr = ('heruilong1988.oicp.net', 23456)
    sock.connect(addr)
    logger.info(u'SOCK dev conn OK')
    sock.setblocking(False)
    sockfd = sock.fileno()

    buflen = 65536
    fds = [tunfd, sockfd, ]
    while True:
        rs, _, _ = select.select(fds, [], [], 0.1)
        for fd in rs:
            if fd == tunfd:
                logger.info('TUN recv DATA')
                os.write(sockfd, os.read(tunfd, buflen))
            elif fd == sockfd:
                logger.info(u'SOCK recv DATA')
                os.write(tunfd, os.read(sockfd, buflen))


def server():
    buflen = 65536
    tundev = make_tun()
    tunfd = tundev.fileno()
    logger.info(u'TUN dev OK')
    subprocess.check_call('ifconfig tun0 192.168.10.1/24 up', shell=True)
    time.sleep(1)

    sock = socket.socket()
    laddr = ('192.168.0.192', 23456)
    sock.bind(laddr)
    sock.listen(socket.SOMAXCONN)
    logger.info(u'Sock Listen OK')
    sock.setblocking(False)
    sockfd = sock.fileno()

    fds = [tunfd, sockfd, ]
    while True:
        rs, _, _ = select.select(fds, [], [], 0.1)
        for fd in rs:
            if fd == sockfd:
                cs, ca = sock.accept()
                logger.info(u'Remote sock addr: [%s:%d]' % ca)
                fds.append(cs.fileno())
            elif fd == tunfd:
                logger.info(u'TUN dev recv DATA, rs:[%r]' % rs)
                for client_fd in fds:
                    if client_fd not in [tunfd, sockfd]:
                        os.write(client_fd, os.read(tunfd, buflen))
            else:
                logger.info(u'SOCK dev recv DATA')
                os.write(tunfd, os.read(fd, buflen))


if __name__ == '__main__':
    if sys.argv[1] == '-s':
        sys.exit(server())
    elif sys.argv[1] == '-c':
        sys.exit(client())
    else:
        print u'Usage: pyvpn [-s] [-c]'
