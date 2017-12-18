open('ip.data','w').write("")

for i in range(130,141):
    open('ip.data','a').write("192.168.1.%d:23333\n"%i)


