from main import dis
from ubinascii import hexlify as b2a_hex

RV.write(b2a_hex(dis.dis.buffer))

