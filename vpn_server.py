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
    clients = {}

    fds = [tunfd, sockfd, ]
    while True:
        try:
            rs, _, _ = select.select(fds, [], [], 0.1)
        except select.error as e:
            print e
            sys.exit(-1)
        for fd in rs:
            if fd == sockfd:
                cs, ca = sock.accept()
                csfd = cs.fileno()
                fds.append(csfd)
                client = Client(cs)
                client.set_tunfd(tunfd)
                clients[csfd] = client
                logger.info(u'Remote sock addr: [%s:%d]' % ca)
            elif fd == tunfd:
                logger.info(u'TUN dev recv, rs:[%r]' % rs)
                for client_fd in fds:
                    if client_fd not in [tunfd, sockfd]:
                        os.write(client_fd, os.read(tunfd, buflen))
            else:
                rcv = os.read(fd, buflen)
                if len(rcv) == 0:
                    print u'SOCK rcv [0]'
                    fds.remove(fd)
                    del clients[fd]
                    continue
                logger.info(u'SOCK recv [%d]' % len(rcv))
                client = clients[fd]
                client.recv(rcv)


if __name__ == '__main__':
    main()
