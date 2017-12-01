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
from optparse import OptionParser

def run():
    global cmd,first_run
    cmd_split_prefix = "/bin/echo %s;"%cmd_prefix
    cmd_split_postfix = ";/bin/echo %s"%cmd_postfix
    # if the target list exsists, load it. or regard it as ip addr
    if os.path.isfile(target_list):
	targets = open(target_list).readlines()
    else:
	targets = [target_list]
    for target in targets:
	target = target[:-1]
        target,target_port = target.split(":")
	reserve = 0
	is_vuln = 1
	info = "error"
	flag = "hello world!"
	try:
	    if func:
		cmd = func(target,target_port,"")
            if first_run:
                cmd = cmd_split_prefix + cmd + cmd_split_postfix
                first_run = 0
            if debug:
                print cmd
            flag,is_vuln,info,reserve = attack(target,target_port,cmd,run_for_flag)
	except Exception,e:
	    if debug:
		print traceback.format_exc()
	    dump_error(str(e),target,load_script)
	#set the return value reverse => 0 and is_vuln => 1 and the flag has  been changed, post the flag.
	if not reserve and  is_vuln and flag!="hello world!":
	    res = post_flag(flag)
	    if res:
		dump_success("get flag success",target,load_script)
	    else:
		dump_error("flag check error",target,load_script)
	elif is_vuln == 0:
	    dump_error("server not vulnerable",target,load_script)
	elif reserve==1:
	    dump_error("reverse flag has been set",target,load_script)
    
    dump_success("one round finished! sleeping...")
    time.sleep(script_runtime_span)
		 
def banner():
    my_banner = ""
    my_banner += "    ___        ______    ___       _       _ \n"
    my_banner += "   / \ \      / /  _ \  |_ _|_ __ | |_ ___| |\n"
    my_banner += "  / _ \ \ /\ / /| | | |  | || '_ \| __/ _ \ |\n"
    my_banner += " / ___ \ V  V / | |_| |  | || | | | ||  __/ |\n"
    my_banner += "/_/   \_\_/\_/  |____/  |___|_| |_|\__\___|_|\n"
    my_banner += "                                             \n"
    my_banner += "                          Hence Zhang@Lancet \n"
    my_banner += "                                             \n"
    print my_banner


if __name__ == '__main__':
    banner()
    parser = OptionParser()
    parser.add_option("-m", "--module",\
                     dest="module", default="sample",\
                      help="Input the attack module here :)")
    
    parser.add_option("-c", "--command",\
                     dest="command", default="get_flag",\
                      help="The command you want to run")
    
    parser.add_option("-r", "--random_ua",\
                     dest="random_ua", default="False",\
                      help="Enable the random UA to avoid filter")
    (options, args) = parser.parse_args()
    load_script = options.module
    cmd = options.command
    if cmd=="get_flag":
	run_for_flag = 1
    attack = __import__(load_script).attack

# if the attack fails, the possible reasons are:
# 1. the server has fixed up that vuln, then add that server to the fail_list
# 2. the server is down, but not fixed, do not add, just skip it this time.
# 3. some other exceptions, just print it out 

    if hasattr(function,cmd):
        func = getattr(function,cmd)
    else:
        func = None

    while 1:
        try:
	    run()
        except  KeyboardInterrupt:
	    dump_error("Program stoped by user, existing...")
	    exit()
        dump_success("------------------------- one round finish -------------------------")
