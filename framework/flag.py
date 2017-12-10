#!/usr/bin/env python
# -*- coding: utf-8 -*-


from http import http
from config import *
from function import *

# if u get the flag string, chk it before the post. If u still get some problems,
# this may blame to : 1.the network failure to flag_server
#		      2.the flag is out of data

#check wether the format of a flag is correct, suppose the format of a flag must be a string with hex value
def check_flag(flag):
    flag = flag.replace(" ","").replace("\n","")
    if not flag:
	return False
    for char in flag:
	if char not in flag_string: 
	    dump_warning("flag => "+flag)
            return False
    return True

def post_flag(flag):
    flag = flag.replace(" ","").replace("\n","")
    try:
	headers['Cookie'] = flag_cookie
	res = http("post",flag_server,flag_port,flag_url,"key="+flag+"&token="+flag_token,headers)
    except Exception,e:
        dump_error("flag post error","flag server","flag.py post_flag")
	return False
    if flag_success_match in res:
	dump_success('get flag success','flag server','flag.py post_flag')
	return True
    return False


	
