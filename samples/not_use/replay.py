#!/usr/bin/env python

from framework.http import http
from framework.function import *
from framework.config import *
import importlib
import requests
import re


def parse_http(filename,number):
    number = int(number)
    lines = open(filename).read()
    lines = replace_string(lines,number)
    lines = lines.split("\n")
    # Get the request line,header,and body
    request_line = lines[0].strip("\n")
    count = 0
    for line in lines:
        if line == '':
            break
        else:
            count += 1
    request_header = lines[1:count]
    request_body = '\n'.join(lines[count+1:])
    # Parse the request line
    method,url,protocol = request_line.split(" ")
    # Parse the header
    tmp = {}
    for header in request_header:
        index = header.find(':')
        tmp[header[:index]] = header[index+2:].strip("\n")
    request_header = tmp
    # Clean the cookie for the request.Session()
    if request_header.has_key('Cookie'):
        dump_warning("we have abandoned the original cookie")
        #del request_header['Cookie']
    
    return method,url,request_header,request_body    

def replace_string(string,number):
    pattern = '^re_(\S)+_%d'%int(number)
    if '{{cmd}}' in string:
        debug_print("{{cmd}} => " + cmd)
        string = string.replace("{{cmd}}",cmd)
    for element in dir(seq):
        # Full match
        res = re.match(pattern,element)
        if res and res.group() == element:
            final_value = getattr(seq,element)
            match_string = "{{" + element[3:-2] + "}}"
            debug_print(match_string + " => " + final_value)
            string = string.replace(match_string,final_value)
    return string 
        
def send_http(info,target,target_port):
    method,url,request_header,request_body = info
    # We need to strip the \n at the end of the request body 
    request_body = request_body.rstrip('\n')
    url = 'http://' + target + ':' + str(target_port) + url
    request_header['Accept-Encoding'] = "default"
    if method == 'GET':
        r = s.request('get',url,timeout=timeout,headers=request_header,allow_redirects=False)
    else:
        r = s.request('post',url, data=request_body,timeout=timeout,headers=request_header,allow_redirects=False)
    return r.headers,r.text

def find_in_string(my_range,string):
    debug_print(string)
    prefix,postfix = my_range
    index_1 = string.find(prefix) 
    index_2 = string.find(postfix)
    if index_1 < 0 or index_2 < 0:
        return ""
    if index_2 < index_1:
        dump_error("index_2 > index_1 in the reply.py")
        return ""
    index_1 += len(prefix)
    return string[index_1:index_2]

        
def parse_response(http_response,number):
    number = int(number)
    response_header,text = http_response
    pattern_var = 'res_re_pattern_%d'%number
    if not hasattr(seq,pattern_var):
        return text 
    pattern = getattr(seq,pattern_var)
    tmp_header = ""
    # Transform the response header from array to string
    for key in response_header:
        tmp_header += key + ":" + response_header[key] 
    debug_print('res =>' + tmp_header)
    tmp = tmp_header + text
    for key in pattern:
        res = find_in_string(pattern[key],tmp)
        if res:
            debug_print(key + " => " + res)
            setattr(seq,key,res)
    return text 

 
def sequence_attack(target,target_port,my_cmd,seq_name='test',number=1):
    global cmd,s,seq
    s = requests.Session()
    cmd = my_cmd
    seq = importlib.import_module('seq.' + seq_name + '.config')    
    dump_info("Using sequence payload to attack")
    for i in range(number):
        i += 1
        res = parse_response(send_http(parse_http('seq/%s/%d.txt'%(seq_name,i),'%d'%i),target,target_port),'%d'%i)
    return res
           
#aprint sequence_attack('mut-orff.org',8080,'ls%20-la','test',4) 


