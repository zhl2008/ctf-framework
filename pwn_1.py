from pwn import *
import hashlib
import codecs
from Crypto.Cipher import AES
import sys



# def DES_decrypt(key,ciphertext):
#     cipher = DES.new(key, DES.MODE_CBC)
#     return cipher.decrypt(ciphertext)

# c = DES.new("1"*0x20,DES.MODE_CBC)
# c2 = c.encrypt("2"*16)
# print c2
# print DES_decrypt("1"*8,c2)
# p = process("./revolver")
p = remote(sys.argv[1],int(sys.argv[2]))
s  = '6543210_' + 'edcba987' + 'mlkjihgf' + 'utsrqpon' + 'CBAzyxwv' + 'KJIHGFED' + 'SRQPONML' + '+ZYXWVUT'
def cal(checksum,pre):	
	ans = ""
	for i in s:
		for j in s:
			for t in s:
				ans = i + j + t
				m = hashlib.md5()
				m.update(pre + ans)
				if m.hexdigest() == checksum:
					# print ans
					return ans
def open_insurance():
	p.recvuntil("action:")
	p.sendline("1")
	p.recvuntil("action:")
	p.sendline("1")
	p.recvuntil("opening:")
	checksum = p.recvuntil("#")[:-1]
	pre = p.recv(13)
	# print checksum,pre,cal(checksum,pre)
	# ss = raw_input()
	p.sendline(cal(checksum,pre))
def chamber():
	p.recvuntil("action:")
	# ss = raw_input()
	p.sendline("2")
def train(v):
	p.recvuntil("action:")
	p.sendline("3")
	p.recvuntil("action:")
	p.sendline("2")
	p.recvuntil("train:")
	p.sendline(str(v))
	
def rule(payload):
	p.recvuntil("action:")
	p.sendline("3")
	p.recvuntil("action:")
	p.sendline("3")
	p.recvuntil("rules:")
	p.sendline(payload)

def getflag():
	p.recvuntil("action:")
	p.sendline("3")
	p.recvuntil("action:")
	p.sendline("1")


chamber()
open_insurance()
# ss = raw_input()
train(-0x80000000 + 1)
getflag()
p.recvuntil("flag:")
cflag = codecs.decode(p.recv(64),'hex')
rule("1"*0xf + "2")
# p.recv()
# p.interactive()
p.recvuntil("3132")
key = codecs.decode(p.recv(64),'hex')
# print len(key)
# key = "1"*0x20
p.close()
cipher = AES.new(key, AES.MODE_CBC,"\x00"*16)
flag1 = cipher.decrypt(cflag[:16])
cipher = AES.new(key, AES.MODE_CBC,"\x00"*16)
flag2 = cipher.decrypt(cflag[16:])
mflag = flag1 + flag2
print mflag


