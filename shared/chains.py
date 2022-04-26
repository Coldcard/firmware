# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# chains.py - Magic values for the coins and altcoins we support
#
import ngu
from uhashlib import sha256
from public_constants import AF_CLASSIC, AF_P2SH, AF_P2WPKH, AF_P2WSH, AF_P2WPKH_P2SH, AF_P2WSH_P2SH
from public_constants import AFC_PUBKEY, AFC_SEGWIT, AFC_BECH32, AFC_SCRIPT, AFC_WRAPPED
from serializations import hash160, ser_compact_size
from ucollections import namedtuple
from opcodes import OP_CHECKMULTISIG

# See SLIP 132 <https://github.com/satoshilabs/slips/blob/master/slip-0132.md>
# for background on these version bytes. Not to be confused with SLIP-32 which involves Bech32.
Slip132Version = namedtuple('Slip132Version', ('pub', 'priv', 'hint'))

# See also:
# - <https://github.com/satoshilabs/slips/blob/master/slip-0132.md>
#   - defines ypub/zpub/Xprc variants
# - <https://github.com/satoshilabs/slips/blob/master/slip-0032.md>
#   - nice bech32 encoded scheme for going forward
# - <https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-September/014907.html>
#   - mailing list post proposed ypub, etc.
#   - from <https://github.com/Bit-Wasp/bitcoin-php/issues/576>
# - also electrum source: electrum/lib/constants.py

class ChainsBase:

    curve = 'secp256k1'
    menu_name = None        # use 'name' if this isn't defined
    core_name = None        # name of chain's "core" p2p software

    # b44_cointype comes from
    #    <https://github.com/satoshilabs/slips/blob/master/slip-0044.md>
    # but without high bit set

    @classmethod
    def msg_signing_prefix(cls):
        # see strMessageMagic ... but usually just the coin's name
        # prefixed w/ a length byte
        return '\x18Bitcoin Signed Message:\n'

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
    def p2sh_address(cls, addr_fmt, witdeem_script):
        # Multisig and general P2SH support
        # - witdeem => witness script for segwit, or redeem script otherwise
        # - redeem script can be generated from witness script if needed.
        # - this function needs a witdeem script to be provided, not simple to make
        # - more verification needed to prove it's change/included address (NOT HERE)
        # - reference: <https://bitcoincore.org/en/segwit_wallet_dev/>
        # - returns: str(address)

        assert addr_fmt & AFC_SCRIPT, 'for p2sh only'
        assert witdeem_script, "need witness/redeem script"

        if addr_fmt & AFC_SEGWIT:
            digest = ngu.hash.sha256s(witdeem_script)
        else:
            digest = hash160(witdeem_script)

        if addr_fmt & AFC_BECH32:
            # bech32 encoded segwit p2sh
            addr = ngu.codecs.segwit_encode(cls.bech32_hrp, 0, digest)
        elif addr_fmt == AF_P2WSH_P2SH:
            # segwit p2wsh encoded as classic P2SH
            addr = ngu.codecs.b58_encode(cls.b58_script + hash160(b'\x00\x20' + digest))
        else:
            # P2SH classic
            addr = ngu.codecs.b58_encode(cls.b58_script + digest)

        return addr

    @classmethod
    def address(cls, node, addr_fmt):
        # return a human-readable, properly formatted address

        if addr_fmt == AF_CLASSIC:
            # olde fashioned P2PKH
            assert len(cls.b58_addr) == 1
            return node.addr_help(cls.b58_addr[0])

        if addr_fmt & AFC_SCRIPT:
            # use p2sh_address() instead.
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
        # - or get setup for that, if msg == None
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

        # P2WPKH
        if ll == 22 and script[0:2] == b'\x00\x14':
            return ngu.codecs.segwit_encode(cls.bech32_hrp, 0, script[2:])

        # P2WSH
        if ll == 34 and script[0:2] == b'\x00\x20':
            return ngu.codecs.segwit_encode(cls.bech32_hrp, 0, script[2:])

        raise ValueError('Unknown payment script', repr(script))

class BitcoinMain(ChainsBase):
    # see <https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp#L140>
    ctype = 'BTC'
    name = 'Bitcoin'
    core_name = 'Bitcoin Core'

    slip132 = {
        AF_CLASSIC:     Slip132Version(0x0488B21E, 0x0488ADE4, 'x'),
        AF_P2WPKH_P2SH: Slip132Version(0x049d7cb2, 0x049d7878, 'y'),
        AF_P2WPKH:      Slip132Version(0x04b24746, 0x04b2430c, 'z'),
        AF_P2WSH_P2SH:  Slip132Version(0x0295b43f, 0x0295b005, 'Y'),
        AF_P2WSH:       Slip132Version(0x02aa7ed3, 0x02aa7a99, 'Z'),
    }

    bech32_hrp = 'bc'

    b58_addr    = bytes([0])
    b58_script  = bytes([5])
    b58_privkey = bytes([128])

    b44_cointype = 0

class BitcoinTestnet(BitcoinMain):
    ctype = 'XTN'
    name = 'Bitcoin Testnet'
    menu_name = 'Testnet: BTC'

    slip132 = {
        AF_CLASSIC:     Slip132Version(0x043587cf, 0x04358394, 't'),
        AF_P2WPKH_P2SH: Slip132Version(0x044a5262, 0x044a4e28, 'u'),
        AF_P2WPKH:      Slip132Version(0x045f1cf6, 0x045f18bc, 'v'),
        AF_P2WSH_P2SH:  Slip132Version(0x024289ef, 0x024285b5, 'U'),
        AF_P2WSH:       Slip132Version(0x02575483, 0x02575048, 'V'),
    }

    bech32_hrp = 'tb'

    b58_addr    = bytes([111])
    b58_script  = bytes([196])
    b58_privkey = bytes([239])

    b44_cointype = 1


def get_chain(short_name):
    # lookup object from name: 'BTC' or 'XTN'
    if short_name == 'BTC':
        return BitcoinMain
    elif short_name == 'XTN':
        return BitcoinTestnet
    else:
        raise KeyError(short_name)

def current_chain():
    # return chain matching current setting
    from glob import settings

    chain = settings.get('chain', None)
    if chain is None:
        return BitcoinMain

    return get_chain(chain)

# Overbuilt: will only be testnet and mainchain.
AllChains = [BitcoinMain, BitcoinTestnet]

def slip32_deserialize(xp):
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
    ( 'BIP-44 / Electrum', "m/44'/{coin_type}'/{account}'/{change}/{idx}", AF_CLASSIC ),
    ( 'BIP-49 (P2WPKH-nested-in-P2SH)', "m/49'/{coin_type}'/{account}'/{change}/{idx}",
            AF_P2WPKH_P2SH ),   # generates 3xxx/2xxx p2sh-looking addresses

    ( 'BIP-84 (Native Segwit P2WPKH)', "m/84'/{coin_type}'/{account}'/{change}/{idx}",
            AF_P2WPKH ),           # generates bc1 bech32 addresses
]


# EOF
