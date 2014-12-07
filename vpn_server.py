#!/usr/bin/env python
# encoding: utf-8
'''
Created on 2014年12月6日

@author: Sunday
server:
eth0: 192.168.0.192/24, listen on eth0 23456, communication with tcp
tun0: 192.168.10.1/24
'''
import fcntl  # @UnresolvedImport
import socket
import select
import os
import logging
import struct
import subprocess
import time
import pdb
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


def main():
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
                    print client_fd, fds
                    if client_fd not in [tunfd, sockfd]:
                        os.write(client_fd, os.read(tunfd, buflen))
            else:
                logger.info(u'SOCK dev recv DATA')
                os.write(tunfd, os.read(fd, buflen))


if __name__ == '__main__':
    main()
