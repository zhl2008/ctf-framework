open('ip.data','w').write("")

for i in range(10,33):
    open('ip.data','a').write("172.16.5.%d:5053\n"%i)


