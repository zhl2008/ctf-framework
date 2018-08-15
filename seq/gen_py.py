#!/usr/bin/env python

import re

my_dir = 'read_flag_qwb'
count = 3

file_dir = '' + my_dir + '/'

res = '''#!/usr/bin/env python

from new_replay import *
import requests
import hashlib
import time

#target = '47.105.121.116'
#target_port = 80
my_hash = hashlib.md5('xxxx' + str(target) + str(target_port) + str(time.time())).hexdigest()
file_dir = '%s'
s = requests.session()

'''%file_dir


for i in range(count):
	content = open(file_dir + '%d.txt' %(i+1)).read()
	rep_strs = re.findall('{{[\w]+}}',content)
	res += '''request_%d = open(file_dir + '%d.txt').read()\n'''%(i+1,i+1)
	for rep_str in rep_strs:
		res += '''request_%d = request_%d.replace('%s','')\n'''%(i+1,i+1,rep_str)

	res += '''reply_%d = send_http(s,parse_http(request_%d),target,target_port)
print reply_%d[1]''' %(i+1,i+1,i+1)
	res += "\n\n"


open('../attack.py','w').write(res)

