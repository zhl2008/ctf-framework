#!/usr/bin/env python

import traceback
from http import http
from config import *
import sys
import time
from flag import *
from function import *
import function
import os
'''
usage: run.py [attack] [cmd] (target_list)

'''
run_for_flag = 0 
load_script = sys.argv[1]
if len(sys.argv) > 2:
    cmd = sys.argv[2]
    if cmd=="get_flag":
	run_for_flag = 1
if len(sys.argv) > 3:
    target_list = sys.argv[3]
attack = __import__(load_script).attack

# if the attack fails, the possible reasons are:
# 1. the server has fixed up that vuln, then add that server to the fail_list
# 2. the server is down, but not fixed, do not add, just skip it this time.
# 3. some other exceptions, just print it out 

if hasattr(function,cmd):
    func = getattr(function,cmd)
else:
    func = None

def run():
    global cmd
    # if the target list exsists, load it. or regard it as ip addr
    if os.path.isfile(target_list):
	targets = open(target_list).readlines()
    else:
	targets = [target_list]
    for target in targets:
	target = target[:-1]
	reserve = 0
	is_vuln = 1
	info = "error"
	flag = "hello world!"
	try:
	    if func:
		cmd = func(target,"")
	    flag,is_vuln,info,reserve = attack(target,cmd,run_for_flag)
	except Exception,e:
	    print traceback.format_exc()
	    dump_error(target,str(e),load_script)
	#set the return value reverse => 0 and is_vuln => 1 and the flag has  been changed, post the flag.
	if not reserve and  is_vuln and flag!="hello world!":
	    res = post_flag(flag)
	    if res:
		dump_success(target,"get flag success",load_script)
	    else:
		dump_error(target,"flag check error",load_script)
	elif is_vuln == 0:
	    dump_error(target,"server not vulnerable",load_script)
	elif reserve==1:
	    dump_error(target, "reverse flag has been set",load_script)
    
    print "[info] one round finished! sleeping..."
    time.sleep(script_runtime_span)
		 


while 1:
    run()
    print "--------------------------------------------------"
