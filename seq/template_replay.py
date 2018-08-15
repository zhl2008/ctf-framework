#!/usr/bin/env python

from new_replay import *
import requests

#target = '47.105.121.116'
#target_port = 80
file_dir = 'seq/shit_upload/'
s = requests.session()


request_1 = open(file_dir + '1.txt').read()
request_1 = request_1.replace('{{}}','')
request_1 = request_1.replace('{{}}','')
reply_1 = send_http(s,parse_http(request_1),target,target_port)
print reply_1[1]


request_2 = open(file_dir + '2.txt').read()
request_2 = request_1.replace('{{}}','')
request_2 = request_1.replace('{{}}','')
reply_2 = send_http(s,parse_http(request_2),target,target_port)
print reply_2[1]








