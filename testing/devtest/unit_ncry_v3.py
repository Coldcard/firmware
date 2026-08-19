import aes256ctr
from ubinascii import unhexlify as a2b_hex

from public_constants import USB_V3_C2D, USB_V3_D2C
from usb import usb_v3_keys, usb_v3_tag


session_key = bytes(range(32))
host_pubkey = bytes(range(64))
dev_pubkey = bytes(range(64, 128))

expect_keys = (
    a2b_hex(b'4ae5bbe99e5565f58383634c28916469c6f9777392c5fc4d16e1a4ccffce51d4'),
    a2b_hex(b'8641e0d7e0e9d7610cd33bc6c6025dd772faaad259bb6492ea59362ab7e284df'),
    a2b_hex(b'176e6002488acf16c63646f483d7965c78b41159863e77710fd069a3c7b4ab32'),
    a2b_hex(b'07bdfcd21c34b50241509b146675a5f06d385242dbaf4d0060e2ccfee819706e'),
)

keys = usb_v3_keys(session_key, host_pubkey, dev_pubkey)
assert keys == expect_keys

request_plaintext = a2b_hex(b'70696e676e6372792d76332d766563746f72')
request_ciphertext = aes256ctr.new(keys[0]).cipher(request_plaintext)
assert request_ciphertext == a2b_hex(
    b'4d90a086a4411368708106e3b6ae321fef9d')
assert usb_v3_tag(keys[1], USB_V3_C2D, 0, request_ciphertext) == a2b_hex(
    b'5fc1cfedaf2be32b1cdb55ce62b48029')

response_plaintext = a2b_hex(b'62696e796e6372792d76332d766563746f72')
response_ciphertext = aes256ctr.new(keys[2]).cipher(response_plaintext)
assert response_ciphertext == a2b_hex(
    b'026d1b5205e4686f3682acab956ac2690efe')
assert usb_v3_tag(keys[3], USB_V3_D2C, 0, response_ciphertext) == a2b_hex(
    b'f79887d299df4e655f887a112a7081d5')
