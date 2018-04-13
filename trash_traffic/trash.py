#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys,os
import time
import hashlib
import httplib
import random
import base64

def trash(target,urls):
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
    for i in xrange(random.randint(1,len(args)-5)):
        payload = []
        payload.append(args[random.randint(1,len(args)-1)]+'='+action_str[random.randint(1,len(action_str)-1)])
        for j in xrange(random.randint(1,6)):
            payload.append(argument_str[random.randint(0,len(argument_str)-1)])
        #print random.randint(0,len(argument_str))
        payload.append(file_str[random.randint(0,len(file_str)-1)])
        payload = ''.join(payload)
        result += payload+'&'
        
    tmp = ''
    for m in xrange(10,30):
            tmp += chr(random.randint(32,127))
    tmp = base64.b64encode(tmp)
    result += args[random.randint(1,len(args))-1]+'='+tmp
    #print result
    return result

#trash(1,2)

                
        



