#!/usr/bin/env python
# encoding: utf-8
'''
Created on 2014年12月6日

@author: Sunday
server:
eth0: 192.168.0.192/24, listen on eth0 23456, communication with tcp
tun0: 192.168.10.1/24

#TODO:
2, Data gzip
3, user auth
4, hub to switch
5, select to epoll
6, test global route
7, traffic counting

protocol:
----------------------------
| |
----------------------------
header, body
1 byte, 4 byte, var byte
data, push-ip, push-route, require-auth, auth-res
'''
import fcntl  # @UnresolvedImport
import socket
import select
import os
import logging
import struct
import time
import sys
logger = logging.getLogger('vpn')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)
PYVPN_VERSION = '0.1'

# find const values
# grep IFF_UP -rl /usr/include/
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


def to_int(s):
    try:
        return int(s)
    except ValueError as _unused:
        return None


class exp_none(object):
    def __init__(self, fn):
        self.fn = fn

    def __call__(self, *args, **kwargs):
        try:
            return self.fn(*args, **kwargs)
        except Exception as e:
            logger.warn(e)
            return None


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


@exp_none
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


@exp_none
def add_route(dest, mask, gw):
    # sudo strace route add -net 192.168.0.0/24 gw 192.168.10.1
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


def conn_to_vpn(addr, port):
    sock = socket.socket()
    addr = (addr, port)
    try:
        sock.connect(addr)
    except socket.error as e:
        print 'Connect to VPN:[%d],[%s]' % (e.errno, e.strerror)
        return None
    sock.setblocking(False)
    return sock


class Transport(object):
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


def client_main(host, port, user, pwd):
    buflen = 65536
    dev, tundev = make_tun()
    tunfd = tundev.fileno()
    sock = conn_to_vpn(host, int(port))
    logger.info(u'TUN dev OK, FD:[%d]' % tunfd)
    iret = ifconfig(dev, ip, netmask)
    if iret is None:
        logger.info(u'ip config %s error' % dev)
        return sys.exit(1)
    iret = add_route('192.168.0.0', '255.255.255.0', '192.168.10.1')
    if iret is None:
        logger.info(u'route config %s error' % dev)
        return sys.exit(1)
    time.sleep(1)

    sock = conn_to_vpn(host, int(port))
    if sock is None:
        print u'SOCK dev Fail'
        sys.exit(-1)
    client = Transport(sock)
    client.set_tunfd(tunfd)
    sockfd = sock.fileno()
    logger.info(u'SOCK dev OK, FD:[%d]' % sockfd)

    fds = [tunfd, sockfd, ]
    while True:
        rs, _, _ = select.select(fds, [], [])
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


def main():
    return client_main('192.168.2.108', 1234, 'sunday', '12345678')


if __name__ == '__main__':
    main()
