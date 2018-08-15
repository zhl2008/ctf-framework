import time
import mitmproxy
from mitmproxy.script import concurrent
import os
import json
import hashlib
import urlparse

log_path = './logs'
#record_socket = ['47.75.2.217:80','www.baidu.com:443','coinx.im:443','ichunqiu.com:443','192.168.244.101:443']
record_socket = ['comp:8803']
not_record_ext = ['.css','.js','.jpg','.png','.ico','.txt','.gif']

@concurrent  # Remove this and see what happens
def request(flow):
    r = flow.request
    if my_filter(r):
        my_record(parse_request(r))

# my functions

def my_filter(r):
    flag = 0
    my_socket = r.host + ":" + str(r.port)
    for socket in record_socket:
        if socket in my_socket:
            flag = 1
    if not flag:
        return False
    if not r.path:
        return False
    ext = '.' + urlparse.urlparse(r.path).path.split('.')[-1]
    if ext in not_record_ext:
        return False
    return True

def parse_request(r):
    my_headers = {}
    for header in r.headers:
        my_headers[header] = r.headers[header]
    url_res = urlparse.urlparse(r.path)
    my_path = url_res.path
    my_query = urlparse.parse_qs(url_res.query)
    my_post = urlparse.parse_qs(r.content)
    info = {"header":my_headers,
            "method":r.method,
            "scheme":r.scheme,
            "host":r.host,
            "port":str(r.port),
            "path":my_path,
            "query_str":url_res.query,
            "query":my_query,
            "content":my_post}
    open('test.txt','a').write(json.dumps(info) + "\n")
    return info

def my_record(info):
    log_dir = log_path + '/' + info['header']['Host'] + '/'
    if not os.path.isdir(log_dir):
        os.system('mkdir -p %s' %log_dir)
    request_digest = info['scheme'] + '://' + info['header']['Host'] + info['path'] + info['query_str'] +':' + info['method']
    request_hash = hashlib.md5(request_digest).hexdigest()
    open(log_dir + request_hash,'w').write(json.dumps(info) + "\n")


