# encoding: utf-8
'''
@author: Sunday
'''
from socket import socket
import struct


def get_conn():
    sock = socket()
    addr = ('192.168.2.108', 1234)
    sock.connect(addr)
    return sock


def recv_body(sock):
    head_buf = sock.recv(2)
    length = struct.unpack('@H', head_buf)[0]
    return sock.recv(length)


def auth(user, pwd):
    sock = get_conn()
    # 2 + 1 + 1 + len(user) + 1 + len(pwd)
    body = chr(0) + chr(len(user)) + user + chr(len(pwd)) + pwd
    head = struct.pack('@H', len(body) + 2)
    sock.send(head + body)
    retbody = recv_body(sock)
    print repr(retbody)
    return sock


def test_auth():
    auth('sunday', '12345678')


def test_getip():
    # sock = auth('sunday', '12345678')
    sock = get_conn()
    body = chr(2)
    head = struct.pack('@H', len(body) + 2)
    sock.send(head + body)
    retbody = recv_body(sock)
    print repr(retbody)
    return sock


if __name__ == '__main__':
    # test_auth()
    test_getip()
