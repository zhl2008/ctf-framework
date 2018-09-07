#!/usr/bin/env python

# Searh for our friend team and the chat server :)
# humensec.txt is the label of the friend team 
# humen.txt is the label of the chat server
# In addition, it can check the specific url of all server

import requests
from framework.config import *


def friend_check(target,target_port):
    url = 'http://%s:%d%s'%(target,int(target_port),friend_label)
    r = requests.get(url,timeout=timeout)
    if r.status_code == 200:
        print '|friend__ok_|',
        return True
    print '|friend_fail|',
    return False

def chat_check(target,target_port):
    url = 'http://%s:%d%s'%(targte,int(target_port),chat_label)
    r = requests.get(url,timeout=timeout)
    if r.status_code == 200:
        print '|chat__ok_|',
        return True
    print '|chat_fail|',
    return False

def url_check(target,target_port):
    url_label = '/themes/garland/2.php'
    url = 'http://%s:%d%s'%(target,int(target_port),url_label)
    r = requests.get(url,timeout=timeout)
    if r.status_code == 200:
        print '|url__ok_|',
        return True
    print '|url_fail|',
    return False

targets = open('data/ip.data').readlines()
for target in targets:
    target,target_port = target.strip("\n").split(":")
    print (target+":"+target_port).ljust(25," ") + " =>   ",
    try:
        url_check(target,target_port)
        #chat_check(target,target_port)
        #friend_check(target,target_port)
    except Exception,e:
        print '|fuck_error|',
    print ''     


