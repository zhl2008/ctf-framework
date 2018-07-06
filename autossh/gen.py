x = ''
for i in range(101,152):
    open('t_3','a').write('www-data:password:172.16.%d.101:22\n'%i)
for i in range(101,152):
    open('t_3','a').write('www-data:password::172.20.%d.102:22\n'%i)
