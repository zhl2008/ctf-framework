open('ip.data','w').write("")

for i in range(1,21):
    open('ip.data','a').write("192.168.%d.12:20002\n"%i)


