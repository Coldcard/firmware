from utils import HexStreamer, Base64Streamer
from ubinascii import unhexlify as a2b_hex
from ubinascii import hexlify as b2a_hex
from ubinascii import a2b_base64, b2a_base64

msg = b'This is a test... 123kljdsf sdlkfjsldfj sdflkj' * 2

def check(decoder, msg, parts):
    tst = b''
    for p in parts:
        for xx in decoder.more(p):
            tst += xx
    assert msg == tst, repr([msg,tst])
    assert not decoder.runt

for encoder, cls in [ (b2a_hex, HexStreamer), (b2a_base64, Base64Streamer) ]:
    hx = encoder(msg)
    check(cls(), msg, [hx])
    for i in range(1, len(hx)-2):
        check(cls(), msg, [hx[0:i], hx[i:]])
        check(cls(), msg, [hx[0:i], b' ', hx[i:]])
        check(cls(), msg, [hx[0:i], b' \n ', hx[i:]])

