open('ip.data','w').write("")

for i in range(1,46):
    open('ip.data','a').write("172.16.%d.171:80\n"%i)


