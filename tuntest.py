#!/usr/bin/env python
# encoding: utf-8
'''
Created on 2014年12月14日

@author: Sunday
'''
import fcntl  # @UnresolvedImport
import logging
import struct
import os
logger = logging.getLogger('vpn')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)
PYVPN_VERSION = '0.1'


def make_tun():
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = TUNSETIFF + 2
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    # Open TUN device file.
    tun = open('/dev/net/tun', 'r+b')
    # Tall it we want a TUN device named tun0.
    ifr = struct.pack('16sH', '', IFF_TUN | IFF_NO_PI)
    ret = fcntl.ioctl(tun, TUNSETIFF, ifr)
    devname, _ = struct.unpack('16sH', ret)
    print devname.strip()
    show_buf(ret)
    # Optionally, we want it be accessed by the normal user.
    fcntl.ioctl(tun, TUNSETOWNER, 1000)
    return tun


def show_buf(buf):
    for pos, word in enumerate(buf):
        if pos and (pos % 16 == 0):
            print ''
        print '%02X' % ord(word),
    print ''


def main():
    tun = make_tun()
    tunfd = tun.fileno()
    while True:
        rcv = os.read(tunfd, 65535)
        print '***********************************************'
        show_buf(rcv)


if __name__ == '__main__':
    main()
