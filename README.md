pyvpn
=====

python vpn server & client.

server:
eth0: 192.168.0.192/24, listen on eth0 23456, communication with tcp
tun0: 192.168.10.1/24


client:
eth0: 192.168.2.108/24
tun0: 192.168.10.2/24
ioctl a tun device;
set 192.168.0.1/24 to this tun;
connect to heruilong1988.oicp.net 23456, establish connection, large conn with heartbeat

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
print ifr
return tun.fileno()


Usage:
vpn -s 192.168.10.1 255.255.255.0

vpn -c 192.168.10.0 255.255.255.0 office.server.org 23456


还可以做一个魔兽监听工具。
