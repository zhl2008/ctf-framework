#!/usr/bin/env python 

from trash import trash
from http import http
import time
import json
import threading
from copy import deepcopy

def generate(file_ptr,hd,input,br):
    if not input:
        #file_ptr.write(hd+br)
        return 0
    for i in input:
        tmp=deepcopy(input)
        tmp[i][0]="{crasolee_para}"
        strs=""
        for i in tmp:
            strs+=i+"="+tmp[i][0]+"&"
        file_ptr.write(hd+strs[:-1]+br)
    return 0

def load_proxy(file_path):
    f = open(file_path,"rb")
    rd = f.readlines()
    fmsg = open("./msg_result","wb")
    for i in rd:#[::-1]:
        pack = json.loads(i)
        if pack['method']=='GET':
            hd = "GET*---craso---*"+pack['path']+"*---craso---*"
            generate(fmsg,hd,pack['query'],"\r\n")
        elif pack['method']=='POST':
            hd = "POST*---craso---*"+pack['path']+"*---craso---*"
            generate(fmsg,hd,pack['content'],"\r\n")
    fmsg.close()
    f.close()
    return 0

file_path='../proxy/test.txt'
load_proxy(file_path)
# f = open(file_path,"rb")
# rd = f.readlines()
# for i in rd[::-1]:
#     pack = json.loads(i)
#     for para in pack['content']:
#         print pack['content'][para]
#     #print pack['content'][]
#     exit()