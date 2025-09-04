# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# chains.py - Magic values for the coins and altcoins we support
#
import ngu
from uhashlib import sha256
from ubinascii import hexlify as b2a_hex
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2TR
from public_constants import AF_P2SH, AF_P2WSH, AF_P2WPKH_P2SH, AF_P2WSH_P2SH
from public_constants import AFC_PUBKEY, AFC_BECH32, AFC_SCRIPT
from public_constants import TAPROOT_LEAF_TAPSCRIPT, TAPROOT_LEAF_MASK
from serializations import hash160, ser_compact_size, disassemble, ser_string
from ucollections import namedtuple
from opcodes import OP_RETURN, OP_1, OP_16
from precomp_tag_hash import TAP_TWEAK_H, TAP_LEAF_H


SINGLESIG_AF = (AF_P2WPKH, AF_CLASSIC, AF_P2TR, AF_P2WPKH_P2SH)

# See SLIP 132 <https://github.com/satoshilabs/slips/blob/master/slip-0132.md>
# for background on these version bytes. Not to be confused with SLIP-32 which involves Bech32.
Slip132Version = namedtuple('Slip132Version', ('pub', 'priv', 'hint'))

# See also:
# - <https://github.com/satoshilabs/slips/blob/master/slip-0132.md>
#   - defines ypub/zpub/Xprc variants
# - <https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-September/014907.html>
#   - mailing list post proposed ypub, etc.
#   - from <https://github.com/Bit-Wasp/bitcoin-php/issues/576>
# - also electrum source: electrum/lib/constants.py

# nLockTime in transaction equal or above this value is a unix timestamp (time_t) not block height.
NLOCK_IS_TIME = const(500000000)


def taptweak(internal_key, tweak=None):
    # BIP 341 states: "If the spending conditions do not require a script path,
    # the output key should commit to an unspendable script path instead of having no script path.
    # This can be achieved by computing the output key point as:
    # Q = P + int(hashTapTweak(bytes(P)))G."
    actual_tweak = internal_key if tweak is None else internal_key + tweak
    tweak = ngu.hash.sha256t(TAP_TWEAK_H, actual_tweak, True)
    xo_pubkey = ngu.secp256k1.xonly_pubkey(internal_key)
    xo_pubkey_tweaked = xo_pubkey.tweak_add(tweak)
    return xo_pubkey_tweaked.to_bytes()

def tapscript_serialize(script, leaf_version=TAPROOT_LEAF_TAPSCRIPT):
    # leaf version is only 7 msb
    lv = leaf_version % TAPROOT_LEAF_MASK
    return bytes([lv]) + ser_string(script)

def tapleaf_hash(script, leaf_version=TAPROOT_LEAF_TAPSCRIPT):
    return ngu.hash.sha256t(TAP_LEAF_H, tapscript_serialize(script, leaf_version), True)


class ChainsBase:

    curve = 'secp256k1'
    menu_name = None        # use 'name' if this isn't defined
    ccc_min_block = 0

    # b44_cointype comes from
    #    <https://github.com/satoshilabs/slips/blob/master/slip-0044.md>
    # but without high bit set

    @classmethod
    def msg_signing_prefix(cls):
        # see strMessageMagic ... but usually just the coin's name
        # prefixed w/ a length byte
        return '\x18Bitcoin Signed Message:\n'

    @classmethod
    def sig_hdr_base(cls, addr_fmt):
        if addr_fmt == AF_CLASSIC:
            return 31
        elif addr_fmt == AF_P2WPKH_P2SH:
            return 35
        elif addr_fmt == AF_P2WPKH:
            return 39
        else:
            raise ValueError

    @classmethod
    def serialize_private(cls, node, addr_fmt=AF_CLASSIC):
        # output a xprv
        return node.serialize(cls.slip132[addr_fmt].priv, True)

    @classmethod
    def serialize_public(cls, node, addr_fmt=AF_CLASSIC):
        # output a xpub
        addr_fmt = AF_CLASSIC if addr_fmt == AF_P2SH else addr_fmt
        return node.serialize(cls.slip132[addr_fmt].pub, False)

    @classmethod
    def deserialize_node(cls, text, addr_fmt):
        # xpub/xprv to object
        addr_fmt = AF_CLASSIC if addr_fmt == AF_P2SH else addr_fmt
        node = ngu.hdnode.HDNode()
        version = node.deserialize(text)
        assert (version == cls.slip132[addr_fmt].pub) \
                or (version == cls.slip132[addr_fmt].priv)
        return node

    @classmethod
    def pubkey_to_address(cls, pubkey, addr_fmt):
        # - renders a pubkey to an address
        # - works only with single-key addresses
        assert not addr_fmt & AFC_SCRIPT

        if addr_fmt == AF_P2TR:
            assert len(pubkey) == 32  # internal
            script = b'\x51\x20' + taptweak(pubkey)
        else:
            keyhash = ngu.hash.hash160(pubkey)
            if addr_fmt == AF_CLASSIC:
                script =  b'\x76\xA9\x14' + keyhash + b'\x88\xAC'
            elif addr_fmt == AF_P2WPKH_P2SH:
                redeem_script = b'\x00\x14' + keyhash
                scripthash = ngu.hash.hash160(redeem_script)
                script = b'\xA9\x14' + scripthash + b'\x87'
            elif addr_fmt == AF_P2WPKH:
                script = b'\x00\x14' + keyhash
            else:
                raise ValueError('bad address template: %s' % addr_fmt)

        return cls.render_address(script)

    @classmethod
    def address(cls, node, addr_fmt):
        # return a human-readable, properly formatted address
        if addr_fmt == AF_P2TR:
            xo_pk = node.pubkey()[1:]
            return ngu.codecs.segwit_encode(cls.bech32_hrp, 1, taptweak(xo_pk))

        if addr_fmt == AF_CLASSIC:
            # olde fashioned P2PKH
            assert len(cls.b58_addr) == 1
            return node.addr_help(cls.b58_addr[0])

        if addr_fmt & AFC_SCRIPT:
            # use chain.render_address
            raise ValueError(hex(addr_fmt))

        # so must be P2PKH, fetch it.
        assert addr_fmt & AFC_PUBKEY
        raw = node.addr_help()
        assert len(raw) == 20

        if addr_fmt & AFC_BECH32:
            # bech32 encoded segwit p2pkh
            return ngu.codecs.segwit_encode(cls.bech32_hrp, 0, raw)

        # see BIP-141, "P2WPKH nested in BIP16 P2SH" section
        assert addr_fmt == AF_P2WPKH_P2SH
        assert len(cls.b58_script) == 1
        digest = hash160(b'\x00\x14' + raw)

        return ngu.codecs.b58_encode(cls.b58_script + digest)

    @classmethod
    def privkey(cls, node):
        # serialize a private key (generally shouldn't be!)
        return node.serialize(cls.b58_privkey, True)

    @classmethod
    def hash_message(cls, msg=None, msg_len=0):
        # Perform sha256 for message-signing purposes (only)
        # - or get setup for that, if msg is None
        s = sha256()

        s.update(cls.msg_signing_prefix())

        msg_len = msg_len or len(msg)

        s.update(ser_compact_size(msg_len))

        if msg is None:
            return s

        s.update(msg)

        return ngu.hash.sha256s(s.digest())


    @classmethod
    def render_value(cls, val, unpad=False):
        # convert nValue from a transaction into human form.
        # - always be precise
        # - return (string, units label)
        from glob import settings
        rz = settings.get('rz', 8)

        if rz == 8:
            # full Bitcoins, for OG's
            unit = cls.ctype
            div = 100000000          # caution: don't use 1E8 here, that's a float
            fmt = '%08d'
        elif rz == 5:
            unit = 'm' + cls.ctype      # includes mXTN
            div = 100000
            fmt = '%05d'
        elif rz == 2:
            unit = 'bits'
            div = 100
            fmt = '%02d'
        elif rz == 0:
            return str(val), 'sats'

        if unpad:
            # show precise value, but no trailing zeros
            if (val % div):
                txt = (('%d.'+fmt) % (val // div, val % div)).rstrip('0')
            else:
                # round amount, omit decimal point
                txt = '%d' % (val // div)
        else:
            # all the zeros & fixed with result
            txt = ('%d.'+fmt) % (val // div, val % div)

        return txt, unit

    @classmethod
    def render_address(cls, script):
        # take a scriptPubKey (part of the TxOut) and convert into conventional human-readable
        # string... aka: the "payment address"

        ll = len(script)

        # P2PKH
        if ll == 25 and script[0:3] == b'\x76\xA9\x14' and script[23:26] == b'\x88\xAC':
            return ngu.codecs.b58_encode(cls.b58_addr + script[3:3+20])

        # P2SH
        if ll == 23 and script[0:2] == b'\xA9\x14' and script[22] == 0x87:
            return ngu.codecs.b58_encode(cls.b58_script + script[2:2+20])

        # segwit v0 (P2WPKH, P2WSH)
        if script[0] == 0 and script[1] in (0x14, 0x20) and (ll-2) == script[1]:
            return ngu.codecs.segwit_encode(cls.bech32_hrp, script[0], script[2:])

        # segwit v1 (P2TR) and later segwit version
        if ll == 34 and (OP_1 <= script[0] <= OP_16) and script[1] == 0x20:
            return ngu.codecs.segwit_encode(cls.bech32_hrp, script[0] - 80, script[2:])

        raise ValueError('Unknown payment script', repr(script))

    @classmethod
    def op_return(cls, script):
        # returns decoded string op return data if script is op return otherwise None
        gen = disassemble(script)
        script_type = next(gen)
        if OP_RETURN not in script_type:
            return

        try:
            data = next(gen)[0]
            if data:
                return data
        except StopIteration:
            pass

        return b""

    @classmethod
    def possible_address_fmt(cls, addr):
        # Given a text (serialized) address, return what
        # address format applies to the address, but
        # for AF_P2SH case, could be: AF_P2SH,  AF_P2WPKH_P2SH, AF_P2WSH_P2SH. .. we don't know
        hrp = cls.bech32_hrp + "1"
        if addr.startswith(hrp):
            if addr.startswith(hrp+'p'):
                # segwit v1 (any ver=1 script or address, but for now just taproot...)
                return AF_P2TR
            elif addr.startswith(hrp+'q'):
                # segwit v0
                return AF_P2WPKH if len(addr) < 55 else AF_P2WSH

            return 0

        try:
            raw = ngu.codecs.b58_decode(addr)
        except ValueError: 
            # not base58, not an error
            return 0

        if raw[0] == cls.b58_addr[0]:
            return AF_CLASSIC
        if raw[0] == cls.b58_script[0]:
            return AF_P2SH

        return 0


class BitcoinMain(ChainsBase):
    # see <https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp#L140>
    ctype = 'BTC'
    name = 'Bitcoin Mainnet'
    ccc_min_block = 892714          # Apr 16/2025

    slip132 = {
        AF_CLASSIC:     Slip132Version(0x0488B21E, 0x0488ADE4, 'x'),
        AF_P2WPKH_P2SH: Slip132Version(0x049d7cb2, 0x049d7878, 'y'),
        AF_P2WPKH:      Slip132Version(0x04b24746, 0x04b2430c, 'z'),
        AF_P2WSH_P2SH:  Slip132Version(0x0295b43f, 0x0295b005, 'Y'),
        AF_P2WSH:       Slip132Version(0x02aa7ed3, 0x02aa7a99, 'Z'),
        AF_P2TR:        Slip132Version(0x0488B21E, 0x0488ADE4, 'x'),
    }

    bech32_hrp = 'bc'

    b58_addr    = bytes([0])
    b58_script  = bytes([5])
    b58_privkey = bytes([128])

    b44_cointype = 0

class BitcoinTestnet(ChainsBase):
    # testnet4 (was testnet3 up until 2025 but all parameters are the same)
    ctype = 'XTN'
    name = 'Bitcoin Testnet 4'

    slip132 = {
        AF_CLASSIC:     Slip132Version(0x043587cf, 0x04358394, 't'),
        AF_P2WPKH_P2SH: Slip132Version(0x044a5262, 0x044a4e28, 'u'),
        AF_P2WPKH:      Slip132Version(0x045f1cf6, 0x045f18bc, 'v'),
        AF_P2WSH_P2SH:  Slip132Version(0x024289ef, 0x024285b5, 'U'),
        AF_P2WSH:       Slip132Version(0x02575483, 0x02575048, 'V'),
        AF_P2TR:        Slip132Version(0x043587cf, 0x04358394, 't'),
    }

    bech32_hrp = 'tb'

    b58_addr    = bytes([111])
    b58_script  = bytes([196])
    b58_privkey = bytes([239])

    b44_cointype = 1


class BitcoinRegtest(ChainsBase):
    ctype = 'XRT'
    name = 'Bitcoin Regtest'

    slip132 = {
        AF_CLASSIC:     Slip132Version(0x043587cf, 0x04358394, 't'),
        AF_P2WPKH_P2SH: Slip132Version(0x044a5262, 0x044a4e28, 'u'),
        AF_P2WPKH:      Slip132Version(0x045f1cf6, 0x045f18bc, 'v'),
        AF_P2WSH_P2SH:  Slip132Version(0x024289ef, 0x024285b5, 'U'),
        AF_P2WSH:       Slip132Version(0x02575483, 0x02575048, 'V'),
        AF_P2TR:        Slip132Version(0x043587cf, 0x04358394, 't'),
    }

    bech32_hrp = 'bcrt'

    b58_addr    = bytes([111])
    b58_script  = bytes([196])
    b58_privkey = bytes([239])

    b44_cointype = 1


def get_chain(short_name):
    # lookup object from name: 'BTC' or 'XTN'
    if short_name is None:
        return BitcoinMain
    if short_name == 'BTC':
        return BitcoinMain
    elif short_name == 'XTN':
        return BitcoinTestnet
    elif short_name == 'XRT':
        return BitcoinRegtest
    else:
        raise KeyError(short_name)

def current_chain():
    # return chain matching current setting
    from glob import settings

    chain = settings.get('chain', None)
    if chain is None:
        return BitcoinMain

    return get_chain(chain)

def current_key_chain():
    c = current_chain()
    if c == BitcoinRegtest:
        # regtest has same extended keys as testnet
        c = BitcoinTestnet
    return c

# Overbuilt: will only be testnet and mainchain.
AllChains = [BitcoinMain, BitcoinTestnet, BitcoinRegtest]

def slip132_deserialize(xp):
    # .. and classify chain and addr-type, as implied by prefix
    node = ngu.hdnode.HDNode()
    version = node.deserialize(xp)

    for ch in AllChains:
        for kk in ch.slip132:
            if ch.slip132[kk].pub == version:
                return node, ch, kk, False
            if ch.slip132[kk].priv == version:
                return node, ch, kk, True

    raise ValueError(hex(version))

# Some common/useful derivation paths and where they may be used.
# see bip49 for meaning of the meta vars
# - single signer only
CommonDerivations = [
    # name, path.format(), addr format
    ( 'BIP-44 / Electrum', "m/44h/{coin_type}h/{account}h/{change}/{idx}", AF_CLASSIC ),
    ( 'BIP-49 (P2WPKH-nested-in-P2SH)', "m/49h/{coin_type}h/{account}h/{change}/{idx}",
            AF_P2WPKH_P2SH ),   # generates 3xxx/2xxx p2sh-looking addresses
    ( 'BIP-84 (Native Segwit P2WPKH)', "m/84h/{coin_type}h/{account}h/{change}/{idx}",
            AF_P2WPKH ),           # generates bc1 bech32 addresses
    ('BIP-86 (Taproot Segwit P2TR)', "m/86h/{coin_type}h/{account}h/{change}/{idx}",
            AF_P2TR),  # generates bc1p bech32m addresses
]

STD_DERIVATIONS = {
    "p2pkh": CommonDerivations[0][1],
    "p2sh-p2wpkh": CommonDerivations[1][1],
    "p2wpkh-p2sh": CommonDerivations[1][1],
    "p2wpkh": CommonDerivations[2][1],
    "p2tr": CommonDerivations[3][1],
}

MS_STD_DERIVATIONS = {
    ("p2sh", "m/45h", AF_P2SH),
    ("p2sh_p2wsh", "m/48h/{coin}h/{acct_num}h/1h", AF_P2WSH_P2SH),
    ("p2wsh", "m/48h/{coin}h/{acct_num}h/2h", AF_P2WSH),
    ('p2tr', "m/48h/{coin}h/{acct_num}h/3h", AF_P2TR),
}

AF_TO_STR_AF = {
    AF_CLASSIC: "p2pkh",
    AF_P2TR: "p2tr",
    AF_P2WPKH: "p2wpkh",
    AF_P2WPKH_P2SH: "p2sh-p2wpkh",
    AF_P2SH: "p2sh",
    AF_P2WSH: "p2wsh",
    AF_P2WSH_P2SH: "p2sh-p2wsh",
}

def parse_addr_fmt_str(addr_fmt):
    # accepts strings and also integers if already parsed
    # integers are coming from USB
    try:
        if isinstance(addr_fmt, int):
            if addr_fmt in [AF_P2WPKH_P2SH, AF_P2WPKH, AF_CLASSIC]:
                return addr_fmt
            else:
                try:
                    addr_fmt = AF_TO_STR_AF[addr_fmt]  # just for error msg
                except: pass
                raise ValueError

        addr_fmt = addr_fmt.lower()
        if addr_fmt in ("p2sh-p2wpkh", "p2wpkh-p2sh"):
            return AF_P2WPKH_P2SH
        elif addr_fmt == "p2pkh":
            return AF_CLASSIC
        elif addr_fmt == "p2wpkh":
            return AF_P2WPKH
        elif addr_fmt == "p2tr":
            return AF_P2TR
        else:
            raise ValueError
    except ValueError:
        raise ValueError("Unsupported address format: '%s'" % addr_fmt)


def af_to_bip44_purpose(addr_fmt):
    # single signature only
    return {AF_CLASSIC: 44,
            AF_P2WPKH_P2SH: 49,
            AF_P2WPKH: 84,
            AF_P2TR: 86}[addr_fmt]

def addr_fmt_label(addr_fmt):
    return {
        AF_CLASSIC: "Classic P2PKH",
        AF_P2WPKH_P2SH: "P2SH-Segwit",
        AF_P2WPKH: "Segwit P2WPKH",
        AF_P2TR: "Taproot P2TR",
        AF_P2WSH: "Segwit P2WSH",
        AF_P2WSH_P2SH: "P2SH-P2WSH",
        AF_P2SH: "Legacy P2SH",
    }[addr_fmt]

def verify_recover_pubkey(sig, digest):
    # verifies a message digest against a signature and recovers
    # the address type and public key that did the signing
    if len(sig) != 65:
        raise ValueError('signature length')

    v = sig[0]
    if 27 <= v <= 34:
        af = AF_CLASSIC
    elif 35 <= v <= 38:
        af = AF_P2WPKH_P2SH
    elif 39 <= v <= 42:
        af = AF_P2WPKH
    else:
        raise ValueError('unsupported recovery id: %d' % v)

    try:
        sig = ngu.secp256k1.signature(sig)
        return af, sig.verify_recover(digest).to_bytes()
    except:
        raise ValueError('invalid signature')

# EOF
