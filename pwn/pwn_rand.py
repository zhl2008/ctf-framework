from pwn import *
import subprocess
import os

# from rand_decode import decode

import sys
 

def get_screen():
    os.system("gnome-screenshot -w -f t.png")

def parse_pic():

    img = Image.open("./t.png")

    print img.size          # (1272, 788)
    img2 = img.crop((0, 650, 400, 750))
    img3 = img2.crop((0, 0, 73, 100))
    img4 = img2.crop((73, 0, 145, 100))
    img5 = img2.crop((0, 0, 73, 100))

    img4.show()


def decode(xxx):

	# xxx = "92:18:B0:C5:A8:8E:A3:65:0A:4F:10:13:77:B7:2D:69:38:A1:BB:11:22:6B:8D:5A:38:A1:BB:11:22:6B:8D:5A:38:A1:BB:11:22:6B:8D:5A:38:A1:BB:11:22:6B:8D:5A:38:A1:BB:11:22:6B:8D:5A:38:A1:BB:11:22:6B:8D:5A:38:A1:BB:11:22:6B:8D:5A:38:A1:BB:11:22:6B:8D:5A:81:55:AE:7C:CD:4D:0A:27:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
	# xxx = "B9:14:B3:C5:26:DB:79:F4:74:68:36:F8:0F:CD:0F:F7:6B:A9:03:85:86:A6:56:D3:99:D0:5F:79:2A:56:89:13:42:CC:F8:55:93:96:E2:47:5E:3E:37:4C:9E:48:04:83:C2:F5:59:5E:29:96:5B:0C:17:37:58:E8:D1:49:DD:FF:38:A1:BB:11:22:6B:8D:5A:38:A1:BB:11:22:6B:8D:5A:81:55:AE:7C:CD:4D:0A:27:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
	flag=""
	for i in xrange(0,len(xxx),24):
		v3=int(xxx[i:12+i].replace(":","").decode('hex')[::-1].encode('hex'),16)
		v4=int(xxx[12+i:24+i].replace(":","").decode('hex')[::-1].encode('hex'),16)
		if v3==0:
			break
		v5=0
		for i in xrange(0,0x20):
			v5 -= 0x61C88647
			v5 &= 0xffffffff
		a3 = [0x31,0x32,0x33,0x34]
		for i in xrange(0,0x20):
			v4 -= ((((v3 + v5)&0xffffffff) ^ ((((16 * v3)&0xffffffff) + a3[2])&0xffffffff) ^ ((v3 >> 5) + a3[3]))&0xffffffff)
			v4 &= 0xffffffff
			v3 -= ((((v4 + v5)&0xffffffff) ^ ((((16 * v4)&0xffffffff) + a3[0])&0xffffffff) ^ ((v4 >> 5) + a3[1]))&0xffffffff)
			v3 &= 0xffffffff
			v5 += 0x61C88647
			v5 &= 0xffffffff
		# print flag
		#print hex(v4&0xffffffff)
		if (v3&0xffffffff)==0:
			break
		flag+=hex(v3&0xffffffff)[2:].decode('hex')[::-1]

		if (v4&0xffffffff)==0:
			break
		flag+= hex(v4&0xffffffff)[2:].decode('hex')[::-1]
	print flag
	return flag

# context.log_level = "debug"

def get_rand(off):
    output = subprocess.Popen(["./case2", str(off)],stdout=subprocess.PIPE).communicate()
    print output[0]
    return output[0]

base = 0x0000555555554000
off = -22
while True:
    try:
        off += 1
        print "off " + str(off)
        # p = process("./randbattle")
        context.log_level="debug"
        # p = remote("192.168.20.13", 20003)
        p = remote(str(sys.argv[1]), 20003)
        # gdb.attach(p, "b *%d\nb *%d\nc" % (base + 0x38F3, base + 0x3484))

        p.sendlineafter("ce:", "2")
        # p.recvuntil("2\n")
        # print p.recv(timeout=1)
        # get_screen()
        # parse_pic()
        output = get_rand(off).split(",")
        tmp = chr(int(output[0], 16)) + chr(int(output[1], 16)) + chr(int(output[2], 16)) + "\x00"
        p.sendafter("se2", tmp)

        p.sendafter("first num:", str(int(output[3], 16)).ljust(4, "\x00"))
        p.sendafter("second num:", str(int(output[4], 16)).ljust(4, "\x00"))
        p.sendafter("third num:", str(int(output[5], 16)).ljust(4, "\x00"))

        p.sendlineafter("Your choice:", "1")
        p.sendafter("first num:", str(int(output[6], 16)).ljust(4, "\x00"))
        p.sendafter("second num:", str(int(output[7], 16)).ljust(4, "\x00"))
        p.sendafter("pass:", "1234\n")

        p.recvuntil("gift:\n")
        xxx = p.recvuntil("\n", drop = True)
        print xxx
        flag = decode(xxx)
        print flag
        # p.close()
        # p.interactive()


    except Exception as e:
        print str(e)
        p.close()
        break
        continue
    
