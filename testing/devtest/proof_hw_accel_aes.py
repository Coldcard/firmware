import utime, ngu, aes256ctr, math

# Cifra
start = utime.ticks_ms()
for i in range(100):
    enc = ngu.aes.CTR(b"a" * 32, "b"*16)
    dec = ngu.aes.CTR(b"a" * 32, "b"*16)
    em = enc.cipher(b"msg" * i)
    dm = dec.cipher(em)
    assert dm == b"msg" * i
end = utime.ticks_ms()
cifra_res = utime.ticks_diff(end, start)


# aes256ctr
start = utime.ticks_ms()
for i in range(100):
    enc = aes256ctr.new(b"a" * 32, "b"*16)
    dec = aes256ctr.new(b"a" * 32, "b"*16)
    em = enc.cipher(b"msg" * i)
    dm = dec.cipher(em)
    assert dm == b"msg" * i
end = utime.ticks_ms()
hwa_res = utime.ticks_diff(end, start)

r = math.ceil(cifra_res / hwa_res)
print("Hardware accelerated AES is approximatelly %dX faster than Cifra AES." % r)
