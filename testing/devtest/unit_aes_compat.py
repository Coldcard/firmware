import ngu, aes256ctr, ujson, ustruct

key = b"a" * 32

bsms_signer = b"""BSMS 1.0
a54044308ceac9b7
[eedff89a/48'/0'/0'/2']xpub6EhJvMneoLWAf8cuyLBLQiKiwh89RAmqXEqYeFuaCEHdHwxSRfzLrUxKXEBap7nZSHAYP7Jfq6gZmucotNzpMQ9Sb1nTqerqW8hrtmx6Y6o
Signer 2 key
H/IHW5dMGYsrRdYEz3ux+kKnkWBtxHzfYkREpnYbco38VnMvIxCbDuf7iu6960qDhBLR/RLjlb9UPtLmCMbczDE="""

bsms_coord = b"""BSMS 1.0
wsh(sortedmulti(2,[b7868815/48'/0'/0'/2']xpub6FA5rfxJc94K1kNtxRby1hoHwi7YDyTWwx1KUR3FwskaF6HzCbZMz3zQwGnCqdiFeMTPV3YneTGS2YQPiuNYsSvtggWWMQpEJD4jXU7ZzEh/**,[eedff89a/48'/0'/0'/2']xpub6EhJvMneoLWAf8cuyLBLQiKiwh89RAmqXEqYeFuaCEHdHwxSRfzLrUxKXEBap7nZSHAYP7Jfq6gZmucotNzpMQ9Sb1nTqerqW8hrtmx6Y6o/**))
/0/*,/1/*
bc1qhs4u273g4azq7kqqpe6vh5wfhasfmrq7nheyzsnq77humd7rwtkqagvakf"""

pws = [dict(xfp=0x4369050f, pw=pw) for pw in ["about abandon about", "@#$%^&*()", "ksjdfh78$%"]]
pws_ser = ujson.dumps(pws).encode()

# mimic real data that we use
TEST_CASES = [
    b'Hello World!',
    pws_ser,
    bsms_coord,
    bsms_signer
]


def secret_msg_exchange(alice, bob, msg):
    e_msg = alice.cipher(msg)
    assert bob.cipher(e_msg) == msg
    return_msg = msg + b"\x00ACK"
    e_msg = bob.cipher(return_msg)
    assert alice.cipher(e_msg) == return_msg


for i, msg in enumerate(TEST_CASES):
    # 16 bytes random IV
    # encrypt with Cifra, decrypt with HW accelerated AES
    iv = ngu.random.bytes(16)
    encrypt = ngu.aes.CTR(key, iv)
    decrypt = aes256ctr.new(key, iv)
    secret_msg_exchange(encrypt, decrypt, msg)
    print("Cifra AES --> HW AES\tIV=0b16\t\tOK")

    # encrypt with HW accelerated AES, decrypt with Cifra
    encrypt = aes256ctr.new(key, iv)
    decrypt = ngu.aes.CTR(key, iv)
    secret_msg_exchange(encrypt, decrypt, msg)
    print("HW AES --> Cifra AES\tIV=0b16\t\tOK")

    # empty IV
    # encrypt with Cifra, decrypt with HW accelerated AES
    encrypt = ngu.aes.CTR(key)
    decrypt = aes256ctr.new(key)
    secret_msg_exchange(encrypt, decrypt, msg)
    print("Cifra AES --> HW AES\tIV=NONE\t\tOK")

    # encrypt with HW accelerated AES, decrypt with Cifra
    encrypt = aes256ctr.new(key)
    decrypt = ngu.aes.CTR(key)
    secret_msg_exchange(encrypt, decrypt, msg)
    print("HW AES --> Cifra AES\tIV=NONE\t\tOK")


print("RANDOM TEST CASES")
for i in range(10):
    key = ngu.random.bytes(32)
    iv = ngu.random.bytes(16)

    msg = (key + iv)
    if i:
        msg = msg * i

    # encrypt with Cifra, decrypt with HW accelerated AES
    encrypt = ngu.aes.CTR(key, iv)
    decrypt = aes256ctr.new(key, iv)
    secret_msg_exchange(encrypt, decrypt, msg)
    print("Cifra AES --> HW AES\tIV=0b16\t\tOK")

    # encrypt with HW accelerated AES, decrypt with Cifra
    encrypt = aes256ctr.new(key, iv)
    decrypt = ngu.aes.CTR(key, iv)
    secret_msg_exchange(encrypt, decrypt, msg)
    print("HW AES --> Cifra AES\tIV=0b16\t\tOK")
