#!/usr/bin/env python
# -*- coding: utf-8 -*-

#####################
#config for basic
first_run = 1
script_runtime_span = 20
cmd = "whoami"
debug = 0
headers = {"User-Agent":"Hence Zhang"}
run_for_flag = 0
cmd_prefix = "HENCE666"
cmd_postfix = "ZHANG777"
timeout = 2
#####################

#############################
# config for data and log
target_list = "data/ip.data"
status_list = "data/status.data"
sys_log = "log/sys.log"
specific_status_log = "log/spec/"
targets_status = ''
############################


###########################################
# get flag
flag_server = "172.16.123.123"
flag_port = 80
flag_url = "/commapi/account/submitFlag"
flag_token = "b1pyte5oiwjd0oxugqv77vtk5qian0sf"
flag_cookie = "PHPSESSID=haozigege-test"
flag_path = '/home/tsctf/go/src/gotsctf2018/flag'


# the server you need to visit to get the flag
get_flag_url = "http://172.16.0.30:8000/flag" 
flag_string = 'TSCTFflagFLAGabcdef0123456789ABCDEF{}-_'
flag_match_string = 'ok'
##########################################

########################################
#config for shell
shell_salt = "haozi"
shell_salt_2 = "haozigege"
#shell_type 1 is for normal php backdoor
shell_type = 2
#shell_type 2 is for undead php backdoor
#shell_type = 2
#shell_type 3 is for weevely backdoor
#shell_type = 3
#######################################


#######################
#config for web path and file path
#The final / should not be delete!!!!!!!!
shell_path = "/files/"
shell_absolute_path = "/var/www/html/web/files/"
crontab_path = "/tmp/"
web_path = '/var/www/html/web/'
######################


######################
#config for reverse_shell
reverse_ip = '192.168.37.133'
reverse_port  =  6666
#####################


#####################
#config for upload_and_execute
U_A_E_flag = 0
upload_file_name = ''
executor = ''
####################

####################
#config for rm file
rm_paths = '/var/www/html/index.php /tmp/* /home/ctf/* /var/www/html/data/settings/install.dat'
rm_index = '/var/www/html/admin.php'
rm_ev_paths = '/tmp/* /var/www/html/* '
###################

####################
#config for rm database
db_user = 'root'
db_passwd = ''
db_name = ['performance_schema','mysql','tpshop2.0']
if not db_passwd:
    my_db_passwd = ""
else:
    my_db_passwd = "-p" + db_passwd
###################

####################
#config for autossh
ssh_password = 'Hence666'
###################

####################
#config for friend check
friend_label = '/humensec.txt'
chat_label = '/server53936ce6eef01d89d066ae900e9a1de5.php'
chat_label = '/humen.txt'
url_label = '/shell.php'
#####################

