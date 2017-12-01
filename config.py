#!/usr/bin/env python

#####################
#config for basic
script_runtime_span = 3
cmd = "whoami"
debug = 0
headers = {"User-agent":"Hence Zhang"}
#####################

#############################
# config for target 
target_list = "data/ip.data"
status_list = "data/status.data"
target_port = 10080
############################


###########################################
# get flag
flag_server = "192.168.2.113"
flag_port = 83
flag_url = "/flag.php"
flag_token = "paomachang" # for user Xyth
flag_path = '/flag'
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
shell_path = "/uploads/"
shell_absolute_path = "/var/www/html/uploads/"
crontab_path = "/tmp/"
######################


######################
#config for reverse_shell
reverse_ip = '118.190.78.155'
reverse_port  =  6666
#####################


#####################
#config for upload_and_execute
U_A_E_flag = 0
upload_file_name = ''
executor = ''
####################



