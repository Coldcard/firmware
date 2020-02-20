#!/usr/bin/env python3
#
# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Repackage and sign the firmware image.
#
import os, sys, struct, pdb, click
from collections import namedtuple
from binascii import b2a_hex
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey
from ecdsa.curves import SECP256k1
from sigheader import *

# list of hardware we are presently supporting
CURRENT_HARDWARE = MK_2_OK | MK_3_OK

# more details about header
header = namedtuple('header', FWH_PY_VALUES)
packed_len = struct.calcsize(FWH_PY_FORMAT)
assert packed_len == FW_HEADER_SIZE, \
            "FWH_PY_FORMAT is wrong: gives %d length, not %d" % (packed_len, FW_HEADER_SIZE)

def pad_to(orig, size, fill=b'\xff'):
    assert len(orig) <= size, "too big; no room for padding: %d > %d" % (len(orig), size)

    return orig.ljust(size, fill)

def align_to(n, alignment):
    # align to # of bytes (a power of two)
    return (n + alignment - 1) & ~(alignment-1)
    
def timestamp(backdate=0):
    # render 16-byte BCD timecode in something like ISO 8601
    import datetime
    n = datetime.datetime.utcnow()
    if backdate:
        n -= datetime.timedelta(days=backdate)

    f = n.strftime('%y%0m%0e%0H%0M%0S0000').encode('ascii')
    assert len(f) == 16
    
    # hex string to binary, but BCD..isn't that just a2b_hex?
    rv = bytes([ ((f[i]& 0xf) << 4) | (f[i+1] & 0xf) for i in range(0, 16, 2)])

    assert len(rv) == 8, len(rv)

    return rv

# Options we want for all commands
@click.group()
def main():
    pass

@main.command()
@click.option('-n', type=int, help='Which key # to make', default=1)
@click.option('--path-pattern', '-p',
                    default='keys/%02d.pem', type=str, help='Where to put results')
def make_keys(n, path_pattern):
    "Constuct new keys (only can be used once)"
    # run once only

    from ecdsa.util import randrange_from_seed__trytryagain

    def make_key_from_seed(seed, curve=SECP256k1):
        secexp = randrange_from_seed__trytryagain(seed, curve.order)
        return SigningKey.from_secret_exponent(secexp, curve)

    assert 1 <= n < 16

    if 0:
        # deterministic
        seed = 'ehllo'
        sk1 = make_key_from_seed("%02d:%s" % (n, seed))
    else:
        # actually used:
        sk1 = make_key_from_seed(os.urandom(128))

    fn = path_pattern % n
    assert not os.path.exists(fn), "Already exists: " + fn

    pubkey = sk1.get_verifying_key()

    open(fn, 'wb').write(sk1.to_pem())
    fn = fn.replace('.pem', '.pubkey')
    open(fn+'.pem', 'wb').write(pubkey.to_pem())
    #open(fn+'.bin', 'wb').write(pubkey.to_string())
    open(fn+'.c', 'wt').write(', '.join('0x%02x'%i for i in pubkey.to_string()))


@main.command('version')
@click.argument('fname')
def show_version(fname):
    # just dump the version number in a form that makes for good filenames
    data = open(fname, 'rb').read()

    hdr = data[FW_HEADER_OFFSET:FW_HEADER_OFFSET+FW_HEADER_SIZE ]

    hdr = header(**dict(zip(FWH_PY_VALUES.split(), struct.unpack(FWH_PY_FORMAT, hdr))))

    ver = str(hdr.version_string.split(b'\0', 1)[0], 'ascii')
    ts = str(b2a_hex(hdr.timestamp), 'ascii')
    built = '20' + '-'.join(ts[i:i+2] for i in range(0, 6, 2))
    built += 'T' + ''.join(ts[i:i+2] for i in range(6, 10, 2))

    print('{built}-v{ver}'.format(built=built, ver=ver))

@main.command('check')
@click.argument('fname', default='firmware-signed.bin')
def readback(fname):
    "Verify pubkey and signature used in binary file"
    data = open(fname, 'rb').read()

    assert data[0:5] != b'DfuSe', "got DFU, expect raw binary"

    hdr = data[FW_HEADER_OFFSET:FW_HEADER_OFFSET+FW_HEADER_SIZE ]

    vals = {}
    for fld, v in zip(FWH_PY_VALUES.split(), struct.unpack(FWH_PY_FORMAT, hdr)):
        vals[fld] = v

        if fld == 'version_string':
            v = str(v.split(b'\0', 1)[0], 'ascii')
        elif fld in ('magic_value'):
            v = hex(v)
        elif fld in ('signature', 'future'):
            v = str(b2a_hex(v), 'ascii')
            v = v[0:16] + ' ... ' + v[-16:]
        elif fld == 'install_flags':
            nv = '0x%x =>' % v
            if v & FWHIF_HIGH_WATER:
                nv += ' HIGH_WATER'
            v = nv
        elif fld == 'hw_compat':
            nv = '0x%x => ' % v
            d = []
            if v & MK_1_OK: d.append('Mk1')
            if v & MK_2_OK: d.append('Mk2')
            if v & MK_3_OK: d.append('Mk3')
            if v & ~(MK_1_OK | MK_2_OK | MK_3_OK):
                d.append('?other?')
            v = nv + '+'.join(d)
        elif fld == 'timestamp':
            v = str(b2a_hex(v), 'ascii')
            nv = '20' + '-'.join(v[i:i+2] for i in range(0, 6, 2)) + ' '
            nv += ':'.join(v[i:i+2] for i in range(6, 6+6, 2))
            v = nv + ' UTC'

        print("%16s: %s" % (fld, v))

    # non-useful value, fixed.
    #print('runtime hdr at: 0x%08x' % (0x08008000 + FW_HEADER_OFFSET))

    a = sha256(data[0:FW_HEADER_OFFSET+FW_HEADER_SIZE-64])
    a.update(data[FW_HEADER_OFFSET+FW_HEADER_SIZE:])
    chk = sha256(a.digest()).digest()

    #print("sha256^2: %s" % b2a_hex(chk).decode('ascii'))

    # from pubkey
    vk = VerifyingKey.from_pem(open("keys/%02d.pubkey.pem" % vals['pubkey_num']).read())

    try:
        ok = vk.verify_digest(vals['signature'], chk)
    except:
        ok = False

    print('%16s: %s' % ("ECDSA Signature", ('CORRECT' if ok else 'Wrong, wrong, wrong!!!')))


@main.command('sign')
@click.argument('version', required=True)
@click.option('--pubkey-num', '-k', type=int, help='Which key # to use for signing', default=0)
@click.option('--high_water', '-h', is_flag=True, help='Mark version as new highwater mark (no downgrades below this version)')
@click.option('--verbose', '-v', default=False, is_flag=True, help='Show numbers related to signature')
@click.option('--force-hw-compat', type=str, metavar='BITMASK', help="Override HW compat field (hex)")
@click.option('--backdate', type=int, metavar='DAYS',
                            help='Make downgrade attack test version', default=0)
@click.option('--resign_file', '-r', type=click.File('rb'),
                help='Replace existing signature', default=None)
@click.option('--outfn', '-o', type=click.Path(),
                help='Output filename', default='firmware-signed.bin')
@click.option('--keydir', type=str, metavar='DIRPATH', help="Where to find priv keys for signing", default='keys')
def doit(keydir, outfn=None, build_dir='l-port/build-COLDCARD', high_water=False,
                        current=False, force_hw_compat=None,
                        version='0.1a', pubkey_num=0, backdate=0, verbose=False, resign_file=None):
    "Add signature into binary file before it becomes a DFU file."

    assert len(version) < 8, "Version string limited to 8 bytes, got: %r" % version
    
    if resign_file:
        whole = resign_file.read()
        vectors = whole[0:FW_HEADER_OFFSET]
        body = whole[FW_HEADER_OFFSET+FW_HEADER_SIZE:]
        #click.echo('%s: %d + (128) + %d size' % (resign_file.name, len(vectors), len(body)))
    else:
        vectors = open(build_dir + '/firmware0.bin', 'rb').read()
        body = open(build_dir + '/firmware1.bin', 'rb').read()

    assert len(vectors) <= FW_HEADER_OFFSET, "isr vectors area is too big!"
    assert len(body) >= FW_MIN_LENGTH, "main firmware is too small: %d" % len(body)

    if force_hw_compat is not None:
        hw_compat = int(force_hw_compat, 16)
        click.echo("Overriding hw_compat field: 0x%02x" % hw_compat)
    else:
        hw_compat = CURRENT_HARDWARE

    body_len = align_to(len(body), 512)
    assert body_len % 512 == 0, body_len

    # pad out 
    vectors = pad_to(vectors, FW_HEADER_OFFSET)
    body = pad_to(body, body_len)
    version = pad_to(version.encode('ascii'), 8, b'\0')

    hdr = header(   magic_value=FW_HEADER_MAGIC,
                    version_string=version,
                    firmware_length=FW_HEADER_OFFSET+FW_HEADER_SIZE+body_len,
                    install_flags=(FWHIF_HIGH_WATER if high_water else 0x0),
                    hw_compat=hw_compat,
                    future=b'\0'*(4*FWH_NUM_FUTURE),
                    signature=b'\xff'*64,
                    pubkey_num=pubkey_num,
                    timestamp=timestamp(backdate) )

    assert FW_MIN_LENGTH <= hdr.firmware_length <= FW_MAX_LENGTH, hdr.firmware_length

    # actual file length limited by size of SPI flash area reserved to txn data/uploads
    USB_MAX_LEN = (786432-128)
    assert hdr.firmware_length <= USB_MAX_LEN, \
        "too big for our USB upgrades: %d = %d bytes too big" % (
            hdr.firmware_length, hdr.firmware_length-USB_MAX_LEN)

    print("Remaining flash space: %d bytes" % (USB_MAX_LEN - hdr.firmware_length))

    binhdr = struct.pack(FWH_PY_FORMAT, *hdr)
    assert len(binhdr) == FW_HEADER_SIZE

    assert len(vectors + binhdr[:-64]) == 0x3fc0
    assert len(vectors + binhdr[:-64]) == 0x3fc0

    hashable = vectors + binhdr[:-64] + body
    fw_hash = sha256(sha256(hashable).digest()).digest()

    assert len(fw_hash) == 32

    if verbose:
        print("Hdr: %s" % repr(hdr))
        print('Hash: %s' % b2a_hex(fw_hash).decode('ascii'))

    # load key
    sk = SigningKey.from_pem(open(f"{keydir}/{pubkey_num:02d}.pem").read())

    from ecdsa.util import sigencode_string
    sig = sk.sign_digest(fw_hash, sigencode=sigencode_string)

    assert len(sig) == 64
    final = binhdr[:-64] + sig
    assert len(final) == FW_HEADER_SIZE

    if verbose:
        print('Signature: %s' % b2a_hex(sig).decode('ascii'))

    open(outfn, 'wb').write(vectors + final + body)

    if verbose:
        print("Wrote: %s" % outfn)
        print("Signed by pubkey=%d install_flags=0x%x" % (hdr.pubkey_num, hdr.install_flags))
                    
# EOF
