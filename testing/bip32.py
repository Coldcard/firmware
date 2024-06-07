# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import hashlib, hmac, bech32
from typing import Union
from io import BytesIO
try:
    from pysecp256k1 import (
        ec_seckey_verify, ec_pubkey_create, ec_pubkey_serialize, ec_pubkey_parse,
        ec_seckey_tweak_add, ec_pubkey_tweak_add, tagged_sha256
    )
    from pysecp256k1.extrakeys import xonly_pubkey_from_pubkey, xonly_pubkey_serialize, xonly_pubkey_tweak_add
except ImportError:
    import ecdsa
    SECP256k1 = ecdsa.curves.SECP256k1
    CURVE_GEN = ecdsa.ecdsa.generator_secp256k1
    CURVE_ORDER = CURVE_GEN.order()
    FIELD_ORDER = SECP256k1.curve.p()
    INFINITY = ecdsa.ellipticcurve.INFINITY

from helpers import hash160, str_to_path
from base58 import encode_base58_checksum, decode_base58_checksum

HARDENED = 2 ** 31

Prv_or_PubKeyNode = Union["PrvKeyNode", "PubKeyNode"]


class InvalidKeyError(Exception):
    """Raised when derived key is invalid"""


def big_endian_to_int(b: bytes) -> int:
    """
    Big endian representation to integer.

    :param b: big endian representation
    :return: integer
    """
    return int.from_bytes(b, "big")


def int_to_big_endian(n: int, length: int) -> bytes:
    """
    Represents integer in big endian byteorder.

    :param n: integer
    :param length: byte length
    :return: big endian
    """
    return n.to_bytes(length, "big")


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    """
    Hash-based message authentication code with sha512

    :param key: secret key
    :param msg: message
    :return: digest bytes
    """
    return hmac.new(key=key, msg=msg, digestmod=hashlib.sha512).digest()


class PrivateKey(object):

    __slots__ = (
        "k",
        "K"
    )

    def __init__(self, sec_exp: Union[bytes, int]):
        """
        Initializes private key.

        :param sec_exp: secret
        """
        if isinstance(sec_exp, int):
            sec_exp = int_to_big_endian(sec_exp, 32)
        try:
            ec_seckey_verify(sec_exp)
            self.k = sec_exp
            self.K = PublicKey(ec_pubkey_create(self.k))
        except NameError:
            k = ecdsa.SigningKey.from_string(sec_exp, curve=SECP256k1)
            self.K = PublicKey(pub_key=k.get_verifying_key())
            self.k = k.to_string()
        else:
            ec_seckey_verify(self.k)
            self.K = PublicKey(ec_pubkey_create(self.k))

    def __bytes__(self) -> bytes:
        """
        Encodes private key into corresponding byte sequence.

        :return: byte representation of PrivateKey object
        """
        return self.k

    def __eq__(self, other: "PrivateKey") -> bool:
        """
        Checks whether two private keys are equal.

        :param other: other private key
        """
        return self.k == other.k

    def wif(self, compressed: bool = True, testnet: bool = False) -> str:
        """
        Encodes private key into wallet import/export format.

        :param compressed: whether public key is compressed (default=True)
        :param testnet: whether to encode as a testnet key (default=False)
        :return: WIF encoded private key
        """
        prefix = b"\xef" if testnet else b"\x80"
        suffix = b"\x01" if compressed else b""
        return encode_base58_checksum(prefix + bytes(self) + suffix)

    def tweak_add(self, tweak32: bytes) -> "PrivateKey":
        tweaked = ec_seckey_tweak_add(self.k, tweak32)
        return PrivateKey(sec_exp=tweaked)

    def address(self, compressed: bool = True, chain: str = "BTC",
                addr_fmt: str = "p2wpkh") -> str:
        return self.K.address(compressed, chain, addr_fmt)

    @classmethod
    def from_wif(cls, wif_str: str) -> "PrivateKey":
        """
        Initializes private key from wallet import format encoding.

        :param wif_str: wallet import format private key
        :return: private key
        """
        decoded = decode_base58_checksum(s=wif_str)
        if wif_str[0] in ("K", "L", "c"):
            # compressed key --> so remove last byte that has to be 01
            assert decoded[-1] == 1
            decoded = decoded[:-1]
        return cls(sec_exp=decoded[1:])

    @classmethod
    def parse(cls, key_bytes: bytes) -> "PrivateKey":
        """
        Initializes private key from byte sequence.

        :param key_bytes: byte representation of private key
        :return: private key
        """
        return cls(sec_exp=key_bytes)

    @classmethod
    def from_int(cls, sec_exp: int) -> "Privatekey":
        return cls(sec_exp=int_to_big_endian(sec_exp, 32))


class PublicKey(object):

    __slots__ = (
        "K"
    )

    def __init__(self, pub_key):
        """
        Initializes PublicKey object.

        :param key: secp256k1 pubkey or ecdsa.VerifyingKey
        """
        self.K = pub_key

    def __eq__(self, other: "PublicKey") -> bool:
        """
        Checks whether two public keys are equal.

        :param other: other public key
        """
        return self.sec() == other.sec()

    @property
    def point(self): # -> ecdsa.ellipticcurve.Point:
        """
        Point on curve (x and y coordinates).

        :return: point on curve
        """
        return self.K.pubkey.point

    def sec(self, compressed: bool = True) -> bytes:
        """
        Encodes public key to SEC format.

        :param compressed: whether to use compressed format (default=True)
        :return: SEC encoded public key
        """
        try:
            return ec_pubkey_serialize(self.K, compressed=compressed)
        except NameError:
            return self.K.to_string(encoding="compressed" if compressed else "uncompressed")

    def tweak_add(self, tweak32: bytes) -> "PublicKey":
        assert len(tweak32) == 32
        return PublicKey(pub_key=ec_pubkey_tweak_add(self.K, tweak32))

    def taptweak(self, tweak32: bytes = None) -> "bytes":
        xonly_key, _ = xonly_pubkey_from_pubkey(self.K)
        tweak = tweak32 or xonly_pubkey_serialize(xonly_key)
        tweak = tagged_sha256(b"TapTweak", tweak)
        tweaked_pubkey = xonly_pubkey_tweak_add(xonly_key, tweak)
        tweaked_xonly_pubkey, parity = xonly_pubkey_from_pubkey(tweaked_pubkey)
        return xonly_pubkey_serialize(tweaked_xonly_pubkey)

    @classmethod
    def parse(cls, key_bytes: bytes) -> "PublicKey":
        """
        Initializes public key from byte sequence.

        :param key_bytes: byte representation of public key
        :return: public key
        """
        try:
            return cls(pub_key=ec_pubkey_parse(key_bytes))
        except NameError:
            return cls(ecdsa.VerifyingKey.from_string(key_bytes, curve=SECP256k1))

    @classmethod
    def from_point(cls, point) -> "PublicKey":
        """
        Initializes public key from point on elliptic curve.

        :param point: point on elliptic curve
        :return: public key
        """
        return cls(ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1))

    def h160(self, compressed: bool = True) -> bytes:
        """
        SHA256 followed by RIPEMD160 of public key.

        :param compressed: whether to use compressed format (default=True)
        :return: SHA256(RIPEMD160(public key))
        """
        return hash160(self.sec(compressed=compressed))

    def address(self, compressed: bool = True, chain: str = "BTC",
                addr_fmt: str = "p2wpkh") -> str:
        """
        Generates bitcoin address from public key.

        :param compressed: whether to use compressed format (default=True)
        :param testnet: whether to encode as a testnet address (default=False)
        :param addr_type: which address type to generate:
                            1. p2pkh
                            2. p2sh-p2wpkh
                            3. p2wpkh (default)
        :return: bitcoin address
        """
        if chain == "BTC":
            hrp = "bc"
            pkh_prefix = b"\x00"
            sh_prefix = b"\x05"
        else:
            pkh_prefix = b"\x6f"
            sh_prefix = b"\xc4"
            if chain == "XRT":
                hrp = "bcrt"
            elif chain == "XTN":
                hrp = "tb"
            else:
                assert False

        if addr_fmt == "p2tr":
            tweaked_xonly = self.taptweak()
            return bech32.encode(hrp=hrp, witver=1, witprog=tweaked_xonly)

        h160 = self.h160(compressed=compressed)
        if addr_fmt == "p2pkh":
            return encode_base58_checksum(pkh_prefix + h160)
        elif addr_fmt == "p2wpkh":
            return bech32.encode(hrp=hrp, witver=0, witprog=h160)
        elif addr_fmt == "p2sh-p2wpkh":
            scr = b"\x00\x14" + h160  # witversion 0 + pubkey hash
            h160 = hash160(scr)
            return encode_base58_checksum(sh_prefix + h160)

        raise ValueError("Unsupported address type.")


class PubKeyNode(object):

    mark: str = "M"
    testnet_version: int = 0x043587CF
    mainnet_version: int = 0x0488B21E

    __slots__ = (
        "parent",
        "key",
        "chain_code",
        "depth",
        "index",
        "parsed_parent_fingerprint",
        "parsed_version",
        "testnet",
        "children"
    )

    def __init__(self, key: bytes, chain_code: bytes, index: int = 0,
                 depth: int = 0, testnet: bool = False,
                 parent: Union["PubKeyNode", "PrvKeyNode"] = None,
                 parent_fingerprint: bytes = None):
        """
        Initializes Pub/PrvKeyNode.

        :param key: public or private key
        :param chain_code: chain code
        :param index: current node derivation index (default=0)
        :param depth: current node depth (default=0)
        :param testnet: whether this node is testnet node (default=False)
        :param parent: parent node of the current node (default=None)
        :param parent_fingerprint: fingerprint of parent node (default=None)
        """
        self.parent = parent
        self.key = key
        self.chain_code = chain_code
        self.depth = depth
        self.index = index
        self.parsed_parent_fingerprint = parent_fingerprint
        self.parsed_version = None
        self.testnet = testnet

    def __eq__(self, other) -> bool:
        """
        Checks whether two private/public key nodes are equal.

        :param other: other private/public key node
        """
        if type(self) != type(other):
            return False
        self_key = big_endian_to_int(self.key)
        other_key = big_endian_to_int(other.key)
        return self_key == other_key and \
            self.chain_code == other.chain_code and \
            self.depth == other.depth and \
            self.index == other.index and \
            self.testnet == other.testnet and \
            self.parent_fingerprint == other.parent_fingerprint

    @property
    def public_key(self) -> PublicKey:
        """
        Public key node's public key.

        :return: public key of public key node
        """
        return PublicKey.parse(key_bytes=self.key)

    @property
    def parent_fingerprint(self) -> bytes:
        """
        Gets parent fingerprint.

        If node is parsed from extended key, only parsed parent fingerprint
        is available. If node is derived, parent fingerprint is calculated
        from parent node.

        :return: parent fingerprint
        """
        if self.parent:
            fingerprint = self.parent.fingerprint()
        else:
            fingerprint = self.parsed_parent_fingerprint
        # in case there is still None here - it is master
        return fingerprint or b"\x00\x00\x00\x00"

    @property
    def pub_version(self) -> int:
        """
        Decides which extended public key version integer to use
        based on testnet parameter.

        :return: extended public key version
        """
        if self.testnet:
            return PubKeyNode.testnet_version
        return PubKeyNode.mainnet_version

    def __repr__(self) -> str:
        if self.is_master() or self.is_root():
            return self.mark
        if self.is_hardened():
            index = str(self.index - 2**31) + "'"
        else:
            index = str(self.index)
        parent = str(self.parent) if self.parent else self.mark
        return parent + "/" + index

    def is_hardened(self) -> bool:
        """Check whether current key node is hardened."""
        return self.index >= 2**31

    def is_master(self) -> bool:
        """Check whether current key node is master node."""
        return self.depth == 0 and self.index == 0 and self.parent is None

    def is_root(self) -> bool:
        """Check whether current key node is root (has no parent)."""
        return self.parent is None

    def fingerprint(self) -> bytes:
        """
        Gets current node fingerprint.

        :return: first four bytes of SHA256(RIPEMD160(public key))
        """
        return hash160(self.public_key.sec())[:4]

    @classmethod
    def parse(cls, s: Union[str, bytes, BytesIO],
              testnet: bool = False) -> Prv_or_PubKeyNode:
        """
        Initializes private/public key node from serialized node or
        extended key.

        :param s: serialized node or extended key
        :param testnet: whether this node is testnet node
        :return: public/private key node
        """
        if isinstance(s, str):
            s = BytesIO(decode_base58_checksum(s=s))
        elif isinstance(s, bytes):
            s = BytesIO(s)
        elif isinstance(s, BytesIO):
            pass
        else:
            raise ValueError("has to be bytes, str or BytesIO")
        return cls._parse(s, testnet=testnet)

    @classmethod
    def _parse(cls, s: BytesIO, testnet: bool = False) -> Prv_or_PubKeyNode:
        """
        Initializes private/public key node from serialized node buffer.

        :param s: serialized node buffer
        :param testnet: whether this node is testnet node (default=False)
        :return: public/private key node
        """
        version = big_endian_to_int(s.read(4))
        depth = big_endian_to_int(s.read(1))
        parent_fingerprint = s.read(4)
        index = big_endian_to_int(s.read(4))
        chain_code = s.read(32)
        key_bytes = s.read(33)
        key = cls(
            key=key_bytes,
            chain_code=chain_code,
            index=index,
            depth=depth,
            testnet=testnet,
            parent_fingerprint=parent_fingerprint,
        )
        key.parsed_version = version
        return key

    def _serialize(self, key: bytes, version: int = None) -> bytes:
        """
        Serializes public/private key node to extended key format.

        :param version: extended public/private key version (default=None)
        :return: serialized extended public/private key node
        """
        # 4 byte: version bytes
        result = int_to_big_endian(version, 4)
        # 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys
        result += int_to_big_endian(self.depth, 1)
        # 4 bytes: the fingerprint of the parent key (0x00000000 if master key)
        if self.is_master():
            result += int_to_big_endian(0x00000000, 4)
        else:
            result += self.parent_fingerprint
        # 4 bytes: child number. This is ser32(i) for i in xi = xpar/i,
        # with xi the key being serialized. (0x00000000 if master key)
        result += int_to_big_endian(self.index, 4)
        # 32 bytes: the chain code
        result += self.chain_code
        # 33 bytes: the public key or private key data
        # (serP(K) for public keys, 0x00 || ser256(k) for private keys)
        result += key
        return result

    def serialize_public(self, version: int = None) -> bytes:
        """
        Serializes public key node to extended key format.

        :param version: extended public key version (default=None)
        :return: serialized extended public key node
        """
        return self._serialize(
            version=self.pub_version if version is None else version,
            key=self.public_key.sec()
        )

    def extended_public_key(self, version: int = None) -> str:
        """
        Base58 encodes serialized public key node. If version is not
        provided (default) it is determined by result of self.pub_version.

        :param version: extended public key version (default=None)
        :return: extended public key
        """
        return encode_base58_checksum(self.serialize_public(version=version))

    def ckd(self, index: int) -> "PubKeyNode":
        """
        The function CKDpub((Kpar, cpar), i) → (Ki, ci) computes a child
        extended public key from the parent extended public key.
        It is only defined for non-hardened child keys.

        * Check whether i ≥ 231 (whether the child is a hardened key).
        * If so (hardened child):
            return failure
        * If not (normal child):
            let I = HMAC-SHA512(Key=cpar, Data=serP(Kpar) || ser32(i)).
        * Split I into two 32-byte sequences, IL and IR.
        * The returned child key Ki is point(parse256(IL)) + Kpar.
        * The returned chain code ci is IR.
        * In case parse256(IL) ≥ n or Ki is the point at infinity,
            the resulting key is invalid, and one should proceed with the next
             value for i.

        :param index: derivation index
        :return: derived child
        """
        if index >= HARDENED:
            raise RuntimeError("failure: hardened child for public ckd")
        I = hmac_sha512(
            key=self.chain_code,
            msg=self.key + int_to_big_endian(index, 4)
        )
        IL, IR = I[:32], I[32:]
        # TODO this does not check whether IL is not zero (secp256k1 also does not check)
        try:
            Ki = self.public_key.tweak_add(IL)
        except NameError:
            if big_endian_to_int(IL) >= CURVE_ORDER:
                InvalidKeyError(
                    "public key {} is greater/equal to curve order".format(
                        big_endian_to_int(IL)
                    )
                )
            point = PrivateKey.parse(IL).K.point + self.public_key.point
            if point == INFINITY:
                raise InvalidKeyError("public key is a point at infinity")
            Ki = PublicKey.from_point(point=point)

        child = self.__class__(
            key=Ki.sec(),
            chain_code=IR,
            index=index,
            depth=self.depth + 1,
            testnet=self.testnet,
            parent=self
        )
        return child


class PrvKeyNode(PubKeyNode):

    mark: str = "m"
    testnet_version: int = 0x04358394
    mainnet_version: int = 0x0488ADE4

    @property
    def private_key(self) -> PrivateKey:
        """
        Private key node's private key.

        :return: public key of private key node
        """
        if len(self.key) == 33 and self.key[0] == 0:
            return PrivateKey(self.key[1:])
        return PrivateKey(self.key)

    @property
    def public_key(self) -> PublicKey:
        """
        Private key node's public key.

        :return: public key of public key node
        """
        return self.private_key.K

    @property
    def prv_version(self) -> int:
        """
        Decides which extended private key version integer to use
        based on testnet parameter.

        :return: extended private key version
        """
        if self.testnet:
            return PrvKeyNode.testnet_version
        return PrvKeyNode.mainnet_version

    @classmethod
    def master_key(cls, bip39_seed: bytes, testnet=False) -> "PrvKeyNode":
        """
        Generates master private key node from bip39 seed.

        * Generate a seed byte sequence S (bip39_seed arg) of a chosen length
          (between 128 and 512 bits; 256 bits is advised) from a (P)RNG.
        * Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
        * Split I into two 32-byte sequences, IL and IR.
        * Use parse256(IL) as master secret key, and IR as master chain code.

        :param bip39_seed: bip39_seed
        :param testnet: whether this node is testnet node (default=False)
        :return: master private key node
        """
        I = hmac_sha512(key=b"Bitcoin seed", msg=bip39_seed)
        # private key
        IL = I[:32]
        # In case IL is 0 or ≥ n, the master key is invalid
        int_left_key = big_endian_to_int(IL)
        if int_left_key == 0:
            raise InvalidKeyError("master key is zero")
        try:
            ec_seckey_verify(IL)
        except NameError:
            if int_left_key >= CURVE_ORDER:
                raise InvalidKeyError(
                    "master key {} is greater/equal to curve order".format(
                        int_left_key
                    )
                )
        # chain code
        IR = I[32:]
        return cls(
            key=IL,
            chain_code=IR,
            testnet=testnet
        )

    def serialize_private(self, version: int = None) -> bytes:
        """
        Serializes private key node to extended key format.

        :param version: extended private key version (default=None)
        :return: serialized extended private key node
        """
        return self._serialize(
            version=self.prv_version if version is None else version,
            key=b"\x00" + bytes(self.private_key)
        )

    def extended_private_key(self, version: int = None) -> str:
        """
        Base58 encodes serialized private key node. If version is not
        provided (default) it is determined by result of self.prv_version.

        :param version: extended private key version (default=None)
        :return: extended private key
        """
        return encode_base58_checksum(self.serialize_private(version=version))

    def ckd(self, index: int) -> "PrvKeyNode":
        """
        The function CKDpriv((kpar, cpar), i) → (ki, ci) computes
        a child extended private key from the parent extended private key:

        * Check whether i ≥ 2**31 (whether the child is a hardened key).
        * If so (hardened child):
            let I = HMAC-SHA512(Key=cpar, Data=0x00 || ser256(kpar) || ser32(i))
            (Note: The 0x00 pads the private key to make it 33 bytes long.)
        * If not (normal child):
            let I = HMAC-SHA512(Key=cpar, Data=serP(point(kpar)) || ser32(i))
        * Split I into two 32-byte sequences, IL and IR.
        * The returned child key ki is parse256(IL) + kpar (mod n).
        * The returned chain code ci is IR.
        * In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid,
            and one should proceed with the next value for i.
            (Note: this has probability lower than 1 in 2**127.)

        :param index: derivation index
        :return: derived child
        """
        if index >= HARDENED:
            # hardened
            data = b"\x00"+bytes(self.private_key) + int_to_big_endian(index, 4)
        else:
            data = self.public_key.sec() + int_to_big_endian(index, 4)
        I = hmac_sha512(key=self.chain_code, msg=data)
        IL, IR = I[:32], I[32:]
        try:
            ki = self.private_key.tweak_add(IL)
            # if ki == PrivateKey.from_int(0):
            #    InvalidKeyError("private key is zero")
        except NameError:
            if big_endian_to_int(IL) >= CURVE_ORDER:
                InvalidKeyError(
                    "private key {} is greater/equal to curve order".format(
                        big_endian_to_int(IL)
                    )
                )
            ki = (int.from_bytes(IL, "big") +
                  big_endian_to_int(bytes(self.private_key))) % CURVE_ORDER
            if ki == 0:
                InvalidKeyError("private key is zero")
            ki = int_to_big_endian(ki, 32)

        child = self.__class__(
            key=bytes(ki),
            chain_code=IR,
            index=index,
            depth=self.depth + 1,
            testnet=self.testnet,
            parent=self
        )
        return child


class BIP32Node:
    def __init__(self, node, netcode="XTN"):
        self.node = node
        self._netcode = netcode

    @classmethod
    def from_master_secret(cls, bip39_seed: bytes, netcode="XTN"):
        return cls(PrvKeyNode.master_key(bip39_seed, False if netcode == "BTC" else True),
                   netcode=netcode)

    @classmethod
    def from_hwif(cls, extended_key):
        assert extended_key[0] in "xt"
        testnet = extended_key[0] == "t"
        if extended_key[1:4] == "prv":
            ek = PrvKeyNode.parse(extended_key, testnet)
        else:
            ek = PubKeyNode.parse(extended_key, testnet)
        return cls(ek, netcode="XTN" if testnet else "BTC")

    def subkey_for_path(self, path):
        path_list = str_to_path(path)
        node = self.node
        for idx in path_list:
            node = node.ckd(idx)
        return BIP32Node(node)

    def hwif(self, as_private=False):
        is_pub = type(self.node) is PubKeyNode
        if is_pub and as_private:
            raise ValueError("no private key")
        if as_private:
            return self.node.extended_private_key()
        return self.node.extended_public_key()

    @classmethod
    def from_wallet_key(cls, extended_key):
        return cls.from_hwif(extended_key)

    def hash160(self, compressed=True):
        return self.node.public_key.h160(compressed)

    def address(self, compressed=True, chain="XTN", addr_fmt="p2pkh"):
        return self.node.public_key.address(compressed, addr_fmt=addr_fmt,
                                            chain=chain)

    def sec(self, compressed=True):
        return self.node.public_key.sec(compressed)

    def fingerprint(self):
        return self.node.fingerprint()

    def netcode(self):
        return self._netcode

    def chain_code(self):
        return self.node.chain_code

    def parent_fingerprint(self):
        return self.node.parent_fingerprint
