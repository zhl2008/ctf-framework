#!/usr/bin/env python

from http import http
from config import *
from function import *

# if u get the flag string, chk it before the post. If u still get some problems,
# this may blame to : 1.the network failure to flag_server
#		      2.the flag is out of data

#check wether the format of a flag is correct, suppose the format of a flag must be a string with hex value
def check_flag(flag):
    flag = flag.replace(" ","").replace("\n","")
    for char in flag:
        if (char<"0" or char>"9") and (char>"f" or char<"a"):
	    dump_warning("flag => "+flag)
            return False
    return True

def post_flag(flag):
    flag = flag.replace(" ","").replace("\n","")
    try:
	res = http("post",flag_server,flag_port,flag_url,"flag="+flag+"&token="+flag_token,headers)
    except Exception,e:
        dump_error("flag post error","flag server","flag.py post_flag")
	return False
    if "success" in res:
	dump_success('get flag success','flag server','flag.py post_flag')
	return True
    return False


	
