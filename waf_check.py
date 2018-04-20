#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# using the simple payloads to check wether there is a waf
#

import requests
from framework.http import http

timeout = 2
url_label = '/index.php'
get_payload = 'fileName=system(eval)&aaa=select,into,union&hash=shell&b=whoami&a=hackbyredbud'
post_payload = 'fileName=system(rm)&fuck=drop&script=alert&upload=1.php'

def waf_check(target,target_port):
    url = 'http://%s:%d%s'%(target,int(target_port),url_label)
    r = requests.post(url,timeout=timeout,headers={"Accept-Encoding":"aasas"})
    res1 = r.text
    res2 = http('post',target,int(target_port),url_label + '?' + get_payload, post_payload,{})
    res2 = res2.decode('utf-8')    
    if res1 == res2:
        print '|url__ok_|',
        return True
    print '|url_fail|',
    return False

targets = open('data/ip.data').readlines()
for target in targets:
    target,target_port = target.strip("\n").split(":")
    print (target+":"+target_port).ljust(25," ") + " =>   ",
    try:
        waf_check(target,target_port)
        #chat_check(target,target_port)
        #friend_check(target,target_port)
    except Exception,e:
        print '|fuck_error|',
        print e
    print ''     


