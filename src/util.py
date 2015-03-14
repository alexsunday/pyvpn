# encoding: utf-8
'''
Created on 2015年3月7日

@author: Sunday
'''
import fcntl  # @UnresolvedImport
import socket
import logging
import struct
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


def enable_tcp_forward():
    logger.info(u'Set ip_forward=1')
    with open('/proc/sys/net/ipv4/ip_forward', 'wb+') as f1:
        f1.seek(0)
        f1.write('1')


def inet_ltoa(addr_long):
    '''
    @summary: 转换 整数 到字符串的IP地址
    :param addr_long: 整数地址，可以直接被ping的地址
    '''
    return socket.inet_ntoa(struct.pack('!I', addr_long))


def inet_atol(addr):
    '''
    @summary: 转换字符串IP地址到整数地址
    :param addr: like '192.168.2.121'
    '''
    return struct.unpack('!I', socket.inet_aton(addr))[0]


def is_valid_netmask(mask):
    '''
    @summary: 校验是否为有效 掩码地址
    :param mask: 字符串类型的掩码地址如 255.255.255.128 => True
    // 255.255.0.255 => False
    '''
    all_mask = [0xffffffff ^ (0xffffffff >> i) for i in range(32)]
    return mask in [inet_ltoa(el) for el in all_mask]


def is_valid_ip(ip):
    """Returns true if the given string is a well-formed IP address.

    Supports IPv4 and IPv6.
    //取自 tornado
    """
    if not ip or '\x00' in ip:
        # getaddrinfo resolves empty strings to localhost, and truncates
        # on zero bytes.
        return False
    try:
        res = socket.getaddrinfo(ip, 0, socket.AF_UNSPEC,
                                 socket.SOCK_STREAM,
                                 0, socket.AI_NUMERICHOST)
        return bool(res)
    except socket.gaierror as e:
        if e.args[0] == socket.EAI_NONAME:
            return False
        raise
    return True


def addr_netaddr(addr, netmask):
    '''
    @summary: 获得某IP地址的网络地址，如 192.168.3.1, 255.255.255.0 => 192.168.3.0
    :param addr: like '192.168.0.23'
    :param netmask: like '255.255.255.0'
    @return: 整形地址
    '''
    return inet_atol(addr) & inet_atol(netmask)


def addr_boardcast(addr, netmask):
    '''
    @summary: 获得某IP的广播地址，192.168.3.123, 255.255.255.0 => 192.168.3.255
    //网络地址是该子网的最小地址，广播地址是该子网的最大地址，中间除却网关地址后剩余可自由分配的其他地址
    :param addr:
    :param netmask:
    '''
    return inet_atol(netmask) ^ 0xffffffff | inet_atol(addr)


class PackageType(object):
    AUTH = 0
    HEARTBEAT = 1
    IFCONFIG = 2
    DATA = 3


class User(object):
    def __init__(self):
        self.flow_count = 0
        self.addr = ''


gl_userlist = {}

__all__ = ['to_int', 'exp_none', 'make_tun',
           'ifconfig', 'add_route', 'enable_tcp_forward',
           'PackageType', 'User', 'gl_userlist']
