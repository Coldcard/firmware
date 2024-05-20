# This work is licensed under a Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License

import hashlib


BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def hash256(s: bytes) -> bytes:
    """
    two rounds of sha256

    :param s: data
    :return: hashed data
    """
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def encode_base58(data: bytes) -> str:
    """
    Encode base58.

    :param data: data to encode
    :return: base58 encoded string
    """
    count = 0
    for c in data:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(data, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(data: bytes) -> str:
    """
    Encode base58 checksum.

    :param data: data to encode
    :return: base58 encoded string with checksum
    """
    return encode_base58(data + hash256(data)[:4])


def decode_base58(s: str) -> bytes:
    """
    Decode base58.

    :param s: base58 encoded string
    :return: decoded data
    """
    num = 0
    for c in s:
        if c not in BASE58_ALPHABET:
            raise ValueError(
                "character {} is not valid base58 character".format(c)
            )
        num *= 58
        num += BASE58_ALPHABET.index(c)

    h = hex(num)[2:]
    h = '0' + h if len(h) % 2 else h
    res = bytes.fromhex(h)

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == BASE58_ALPHABET[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res


def decode_base58_checksum(s: str) -> bytes:
    """
    Decode base58 checksum.

    :param s: base58 encoded string with checksum
    :return: decoded data (without checksum)
    """
    num_bytes = decode_base58(s=s)
    checksum = num_bytes[-4:]
    if hash256(num_bytes[:-4])[:4] != checksum:
        raise ValueError(
            'bad checksum: {} {}'.format(
                checksum,
                hash256(num_bytes[:-4])[:4]
            )
        )
    return num_bytes[:-4]

