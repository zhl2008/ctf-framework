import httplib
import urllib2
import ssl 

#ssl._create_default_https_context = ssl._create_unverified_context
 
__doc__ = 'http(method,host,port,url,data,headers)'

def http(method,host,port,url,data,headers):
    con=httplib.HTTPConnection(host,port,timeout=2)
    if method=='post' or method=='POST':
        headers['Content-Length']=len(data)
        headers['Content-Type']='application/x-www-form-urlencoded'  
        con.request("POST",url,data,headers=headers)
    else:
        headers['Content-Length'] = 0    
        con.request("GET",url+'?'+data,headers=headers)
    res = con.getresponse()
    if res.getheader('set-cookie'):
        #headers['Cookie'] = res.getheader('set-cookie')
        extra =  "here is your cookie: " + res.getheader('set-cookie')
    else:
        extra = ""
    if res.getheader('Location'):
        print "Your 302 direct is: "+res.getheader('Location')
    a = res.read() + extra
    con.close()
    return a


def https(method,host,port,url,data,headers):
    url = 'https://' + host + ":" + str(port) + url
    req = urllib2.Request(url,data,headers)
    response = urllib2.urlopen(req)
    return response.read()
  
