open('ip.data','w').write("")

for i in range(101,142):
    open('ip.data','a').write("172.20.%d.101:80\n"%i)


