# slow replacement for ARM assembly code module
import ngu

def new(key, nonce=None):
    assert len(key) == 32  # only 256 bit keys allowewd in C module
    if nonce is not None:
        assert len(nonce) <= 16
    return ngu.aes.CTR(key, nonce or bytes(16))

