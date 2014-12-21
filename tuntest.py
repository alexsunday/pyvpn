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
import socket
from IPython import embed
logger = logging.getLogger('vpn')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)
PYVPN_VERSION = '0.1'

IFF_UP = 0x1
IFF_RUNNING = 0x40
IFNAMSIZ = 16
SIOCSIFADDR = 0x8916
SIOCSIFNETMASK = 0x891c
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SIOCADDRT = 0x890B
RTF_UP = 0x0001
RTF_GATEWAY = 0x0002

AF_INET = socket.AF_INET


def ifconfig(dev, ipaddr, netmask):
    # http://stackoverflow.com/questions/6652384/how-to-set-the-ip-address-from-c-in-linux
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_IP)
    AF_INET = socket.AF_INET
    fd = sock.fileno()
    addrbuf = struct.pack('BBBB', *[int(el) for el in ipaddr.split('.')])
    maskbuf = struct.pack('BBBB', *[int(el) for el in netmask.split('.')])
    sockaddr_mt = '16sHH4s'
    flags_mt = '16sH'
    # ADDR
    siocsifaddr = struct.pack(sockaddr_mt, dev, AF_INET, 0, addrbuf)
    fcntl.ioctl(fd, SIOCSIFADDR, siocsifaddr)
    # MASK
    siocsifnetmask = struct.pack(sockaddr_mt, dev, AF_INET, 0, maskbuf)
    fcntl.ioctl(fd, SIOCSIFNETMASK, siocsifnetmask)
    # ifconfig tun0 up
    ifr2 = struct.pack(flags_mt, dev, 0)
    ifr_ret = fcntl.ioctl(fd, SIOCGIFFLAGS, ifr2)
    cur_flags = struct.unpack(flags_mt, ifr_ret)[1]
    flags = cur_flags | (IFF_UP | IFF_RUNNING)
    ifr_ret = struct.pack(flags_mt, dev, flags)
    ifr_ret = fcntl.ioctl(fd, SIOCSIFFLAGS, ifr_ret)
    return 0


def make_tun():
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = TUNSETIFF + 2
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    # Open TUN device file.
    tun = open('/dev/net/tun', 'r+b')
    # Tall it we want a TUN device named tun0.
    ifr = struct.pack('16sH', 'tun%d', IFF_TUN | IFF_NO_PI)
    ret = fcntl.ioctl(tun, TUNSETIFF, ifr)
    dev, _ = struct.unpack('16sH', ret)
    dev = dev.strip()
    # Optionally, we want it be accessed by the normal user.
    fcntl.ioctl(tun, TUNSETOWNER, 1000)
    return dev, tun


def show_buf(buf):
    for pos, word in enumerate(buf):
        if pos and (pos % 16 == 0):
            print ''
        print '%02X' % ord(word),
    print ''


class Transport(object):
    pass


class Waiter(object):
    def __init__(self):
        pass

    def serve(self):
        pass

    def add(self):
        pass

    def remove(self):
        pass


def add_route(dev, dest, mask, gw):
    # sudo strace route add -net 192.168.0.0/24 gw 192.168.10.1 tun0
    # ioctl(3, SIOCADDRT, ifr)
    # /usr/include/net/route.h
    pad = '\x00' * 8
    inet_aton = socket.inet_aton
    sockaddr_in_fmt = 'hH4s8s'
    rtentry_fmt = 'L16s16s16sH38s'
    dst = struct.pack(sockaddr_in_fmt, AF_INET, 0, inet_aton(dest), pad)
    next_gw = struct.pack(sockaddr_in_fmt, AF_INET, 0, inet_aton(gw), pad)
    netmask = struct.pack(sockaddr_in_fmt, AF_INET, 0, inet_aton(mask), pad)
    rt_flags = RTF_UP | RTF_GATEWAY
    rtentry = struct.pack(rtentry_fmt,
                          0, dst, next_gw, netmask, rt_flags, '\x00' * 38)
    sock = socket.socket(AF_INET, socket.SOCK_DGRAM, 0)
    fcntl.ioctl(sock.fileno(), SIOCADDRT, rtentry)
    return 0


class SelectWait(Waiter):
    pass


class EPollWait(Waiter):
    pass


def main():
    embed()
    dev, tun = make_tun()
    tunfd = tun.fileno()
    print 'Allocated ', dev
    ifconfig(dev, '192.168.10.2', '255.255.255.0')
    embed()
    while True:
        rcv = os.read(tunfd, 65535)
        print '***********************************************'
        show_buf(rcv)
        os.write(tunfd, rcv)


if __name__ == '__main__':
    main()
