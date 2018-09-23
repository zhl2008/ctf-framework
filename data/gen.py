open('ip.data','w').write("")

for i in range(1,40):
    open('ip.data','a').write("172.18.%d.1:8088\n"%i)


