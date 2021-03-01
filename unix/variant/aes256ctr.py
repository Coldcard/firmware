# slow replacement for ARM assembly code module
import ngu

def new(key, nonce=None):
    return ngu.aes.CTR(key, nonce or bytes(16))

