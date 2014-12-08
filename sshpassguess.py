#!/usr/bin/env python
# encoding: utf-8

import gevent
from gevent import monkey
monkey.patch_socket()
monkey.patch_thread()


def main():
    pass


if __name__ == '__main__':
    main()
