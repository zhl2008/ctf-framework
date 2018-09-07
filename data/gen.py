open('ip.data','w').write("")

for i in range(10,61):
    open('ip.data','a').write("172.16.5.%d:5066\n"%i)


