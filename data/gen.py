open('ip.data','w').write("")

for i in range(101,116):
    open('ip.data','a').write("10.0.3.%d:80\n"%i)


