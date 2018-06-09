open('ip.data','w').write("")

for i in range(1,18):
    open('ip.data','a').write("172.16.10.%d:28080\n"%i)


