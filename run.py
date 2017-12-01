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


def attack(target,target_port,cmd,get_flag):
    is_vuln = 1
    flag = "hello world!"
    info = "success"
    reserve = 0    

    if check_shell(target,target_port,""):
	dump_success("check_shell success",target+":"+str(target_port),"function.py check_shell")
	res = execute_shell(target,target_port,cmd)
    else:
	dump_warning("check_shell failed",target+":"+str(target_port),"function.py check_shell")
    
    # Here we use the vulnerability we found in the source code
    res = vulnerable_attack(target,target_port,cmd)
    res = res_filter(res)
    if get_flag:
	if check_flag(res):
	    flag = res
	    dump_info("flag => " + res.replace(" ","").replace("\n",""))
	else:
	    dump_warning("flag format error,you may need to rewrite the shell", target+":"+str(target_port) ,"sample.py attack")
    elif res=="error":
	pass
    else:
	dump_success("execution cmd",target+":"+str(target_port),"sample.py")
        dump_context(res)

    return flag,is_vuln,info,reserve 

def run():
    global raw_cmd,cmd,first_run
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
	    # Save the raw cmd
	    if first_run:
		raw_cmd = cmd
                first_run = 0
	    dump_success("**** start attack %s with %s ****"%(target+":"+target_port,raw_cmd))
	    # Use the func in function.py to translate the cmd to real cmd
	    if func:
		cmd = cmd_split_prefix + func(target,target_port,"") + cmd_split_postfix
            else:
                cmd = cmd_split_prefix + raw_cmd + cmd_split_postfix
	    debug_print(cmd)
            flag,is_vuln,info,reserve = attack(target,target_port,cmd,run_for_flag)
	except Exception,e:
	    debug_print(traceback.format_exc())
	    dump_error(str(e),target,load_script)
	
	dump_success("**** finish attack %s with %s ****"%(target+":"+target_port,raw_cmd))
	#set the return value reverse => 0 and is_vuln => 1 and the flag has  been changed, post the flag.
	if not reserve and  is_vuln and flag!="hello world!":
	    res = post_flag(flag)
	    if res:
		dump_success("get flag success",target+":"+str(target_port),load_script)
	    else:
		dump_error("flag check error",target+":"+str(target_port),load_script)
	elif is_vuln == 0:
	    dump_error("server not vulnerable",target+":"+str(target_port),load_script)
	elif reserve==1:
	    dump_error("reverse flag has been set",target+":"+str(target_port),load_script)
    
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
    dump_info("Start the AWD Intel to hack the planet :)")
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
    vulnerable_attack = __import__(load_script).vulnerable_attack

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
	print ""
        dump_info("--------------------- one round finish -----------------------")
	print ""
