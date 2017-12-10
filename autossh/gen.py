x = ''
for i in range(1,254):
    open('t_3','a').write('ctf:humensec444:172.16.0.%d:22\n'%i)
for i in range(60,70):
    open('t_3','a').write('ubuntu:humensec444:172.16.0.%d:22\n'%i)
for i in range(60,70):
    open('t_3','a').write('pwn4:humensec444:172.16.0.%d:22\n'%i)
