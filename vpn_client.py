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
    print ifr, tun.fileno()
    return tun


def main():
    tundev = make_tun()
    tunfd = tundev.fileno()
    logger.info(u'TUN dev OK')
    subprocess.check_call('ifconfig tun0 192.168.10.2/24 up', shell=True)
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


if __name__ == '__main__':
    main()
