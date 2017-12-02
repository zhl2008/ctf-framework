#!/usr/bin/env python

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
flag_server = "172.17.0.1"
flag_port = 83
flag_url = "/flag2.php"
flag_token = "haozigege" # for user Xyth
flag_path = '/flag'
# the server you need to visit to get the flag
get_flag_url = "http://172.17.0.2:80/flag.php" 
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
shell_path = "/Uploads/"
shell_absolute_path = "/var/www/html/Uploads/"
crontab_path = "/tmp/"
######################


######################
#config for reverse_shell
reverse_ip = '172.17.0.1'
reverse_port  =  6666
#####################


#####################
#config for upload_and_execute
U_A_E_flag = 0
upload_file_name = ''
executor = ''
####################



