# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# utils.py - Misc utils. My favourite kind of source file.
#
import gc, sys, ustruct, ngu, chains, ure, time
from ubinascii import unhexlify as a2b_hex
from ubinascii import hexlify as b2a_hex
from ubinascii import a2b_base64, b2a_base64
from uhashlib import sha256
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH

B2A = lambda x: str(b2a_hex(x), 'ascii')

try:
    from font_iosevka import FontIosevka
    DOUBLE_WIDE = FontIosevka.DOUBLE_WIDE
except ImportError:
    DOUBLE_WIDE = ''

class imported:
    # Context manager that temporarily imports
    # a list of modules.
    # LATER: doubtful this saves any memory when all the code is frozen.

    def __init__(self, *modules):
        self.modules = modules

    def __enter__(self):
        # import everything required
        rv = tuple(__import__(n) for n in self.modules)

        return rv[0] if len(self.modules) == 1 else rv

    def __exit__(self, exc_type, exc_value, traceback):

        for n in self.modules:
            if n in sys.modules:
                del sys.modules[n]

        # recovery that tasty memory.
        gc.collect()

# class min_dramatic_pause:
#     # insure that something takes at least N ms
#     def __init__(self, min_time):
#         import utime
# 
#         self.min_time = min_time
#         self.start_time = utime.ticks_ms()
#     
#     def __enter__(self):
#         pass
# 
#     def __exit__(self, exc_type, exc_value, traceback):
#         import utime
# 
#         if exc_type is not None: return
# 
#         actual = utime.ticks_ms() - self.start_time
#         if actual < self.min_time:
#             utime.sleep_ms(self.min_time - actual)
# 

def pretty_delay(n):
    # decode # of seconds into various ranges, need not be precise.
    if n < 120:
        return '%d seconds' % n
    n /= 60
    if n < 60:
        return '%d minutes' % n
    n /= 60
    if n < 48:
        return '%.1f hours' % n
    n /= 24
    return 'about %.1f days' % n

def pretty_short_delay(sec):
    # precise, shorter on screen display
    if sec >= 3600:
        return '%2dh %2dm %2ds' % (sec //3600, (sec//60) % 60, sec % 60)
    else:
        return '%2dm %2ds' % ((sec//60) % 60, sec % 60)

def pop_count(i):
    # 32-bit population count for integers
    # from <https://stackoverflow.com/questions/9829578>
    i = i - ((i >> 1) & 0x55555555)
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333)

    return (((i + (i >> 4) & 0xF0F0F0F) * 0x1010101) & 0xffffffff) >> 24

def get_filesize(fn):
    # like os.path.getsize()
    import uos
    try:
        return uos.stat(fn)[6]
    except OSError:
        return 0

class HexWriter:
    # Emulate a file/stream but convert binary to hex as they write
    def __init__(self, fd):
        self.fd = fd
        self.pos = 0
        self.checksum = sha256()

    def __enter__(self):
        self.fd.__enter__()
        return self

    def __exit__(self, *a, **k):
        self.fd.seek(0, 2)          # go to end
        self.fd.write(b'\r\n')
        return self.fd.__exit__(*a, **k)

    def tell(self):
        return self.pos

    def write(self, b):
        self.checksum.update(b)
        self.pos += len(b)
        self.fd.write(b2a_hex(b))

    def seek(self, offset, whence=0):
        assert whence == 0          # limited support
        self.pos = offset
        self.fd.seek((2*offset), 0)

    def read(self, ll):
        b = self.fd.read(ll*2)
        if not b:
            return b
        assert len(b)%2 == 0
        self.pos += len(b)//2
        return a2b_hex(b)

    def readinto(self, buf):
        b = self.read(len(buf))
        buf[0:len(b)] = b
        return len(b)

class CapsHexWriter(HexWriter):
    # omit newlines at end, and do CAPS ... better for QR usage
    def write(self, b):
        self.checksum.update(b)
        self.pos += len(b)
        self.fd.write(b2a_hex(b).upper())       # uppercase

    def __exit__(self, *a, **k):
        # dont do the newline thing at end
        return self.fd.__exit__(*a, **k)

class Base64Writer:
    # Emulate a file/stream but convert binary to Base64 as they write
    def __init__(self, fd):
        self.fd = fd
        self.runt = b''

    def __enter__(self):
        self.fd.__enter__()
        return self

    def __exit__(self, *a, **k):
        if self.runt:
            self.fd.write(b2a_base64(self.runt))
        self.fd.write(b'\r\n')
        return self.fd.__exit__(*a, **k)

    def write(self, buf):
        if self.runt:
            buf = self.runt + buf
        rl = len(buf) % 3
        self.runt = buf[-rl:] if rl else b''
        if rl < len(buf):
            tmp = b2a_base64(buf[:(-rl if rl else None)])
            # library puts in newlines!?
            assert tmp[-1:] == b'\n', tmp
            assert tmp[-2:-1] != b'=', tmp
            self.fd.write(tmp[:-1])

def b2a_base64url(s):
    # see <https://datatracker.ietf.org/doc/html/rfc4648#section-5>
    return b2a_base64(s).rstrip(b'=\n').replace(b'+', b'-').replace(b'/', b'_')

def swab32(n):
    # endian swap: 32 bits
    return ustruct.unpack('>I', ustruct.pack('<I', n))[0]

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    return b2a_hex(ustruct.pack('<I', xfp)).decode().upper()

def str2xfp(txt):
    # Inverse of xfp2str
    return ustruct.unpack('<I', a2b_hex(txt))[0]

def is_ascii(s):
    if len(s) == len(s.encode()):
        return True
    return False

def is_printable(s):
    PRINTABLE = range(32, 127)
    for ch in s:
        if ord(ch) not in PRINTABLE:
            return False
    return True

def to_ascii_printable(s, strip=False):
    try:
        s = str(s, 'ascii')
        if strip:
            s = s.strip()
        assert is_ascii(s)
        assert is_printable(s)
        return s
    except:
        raise AssertionError('must be ascii printable')


def problem_file_line(exc):
    # return a string of just the filename.py and line number where
    # an exception occured. Best used on AssertionError.
    import uio, sys, ure

    tmp = uio.StringIO()
    sys.print_exception(exc, tmp)
    lines = tmp.getvalue().split('\n')[-3:]
    del tmp

    # convert: 
    #   File "main.py", line 63, in interact
    #    into just:
    #   main.py:63
    #
    # on simulator, huge path is included, remove that too

    rv = None
    for ln in lines:
        mat = ure.match(r'.*"(/.*/|)(.*)", line (.*), ', ln)
        if mat:
            try:
                rv = mat.group(2) + ':' + mat.group(3)
            except: pass

    return rv or str(exc) or 'Exception'

def cleanup_deriv_path(bin_path, allow_star=False):
    # Clean-up path notation as string.
    # - raise exceptions on junk
    # - standardize on 'hard' notation, not 'prime' (34h not 34' nor 34p)
    # - assume 'm' prefix, so '34' becomes 'm/34', etc
    # - do not assume /// is m/0/0/0
    # - if allow_star, then final position can be * or *h (wildcard)
    import ure
    from public_constants import MAX_PATH_DEPTH

    s = to_ascii_printable(bin_path, strip=True).lower()

    # empty string is valid
    if s == '': return 'm'

    # convert to "hard" rather that "prime" notations
    s = s.replace('p', 'h').replace("'", 'h')

    # regex for valid chars, m at start, maybe /*h or /* at end sometimes
    mat = ure.match(r"(m|m/|)[0-9/h]*" + ('' if not allow_star else r"(\*h|\*|)"), s)
    assert mat.group(0) == s, "invalid characters"

    parts = s.split('/')

    # the m/ prefix is optional
    if parts and parts[0] == 'm':
        parts = parts[1:]

    # master key, just 'm', rather than: 'm/'
    if not parts:
        return 'm'

    assert len(parts) <= MAX_PATH_DEPTH, "too deep"

    for p in parts:
        assert p and p != 'h', "empty path component"
        if allow_star and '*' in p:
            # star or '*h' can be last only (checked by regex above)
            assert p == '*' or p == "*h", "bad wildcard"
            continue
        if p[-1] == "h":
            p = p[0:-1]
        try:
            ip = int(p, 10)
        except:
            ip = -1 
        assert 0 <= ip < 0x80000000 and p == str(ip), "bad component: "+p
            
    return 'm/' + '/'.join(parts)

def keypath_to_str(bin_path, prefix='m/', skip=1):
    # take binary path, like from a PSBT and convert into text notation
    rv = prefix + '/'.join(str(i & 0x7fffffff) + ("h" if i & 0x80000000 else "")
                            for i in bin_path[skip:])
    return 'm' if rv == 'm/' else rv

def str_to_keypath(xfp, path):
    # Take a numeric xfp, and string derivation, and make a list of numbers,
    # like occurs in a PSBT.
    # - no error checking here

    rv = [xfp]
    for i in path.split('/'):
        if i == 'm': continue
        if not i: continue      # trailing or duplicated slashes

        if i[-1] in "'h":
            here = int(i[:-1]) | 0x80000000
        else:
            here = int(i)

        rv.append(here)

    return rv

def match_deriv_path(patterns, path):
    # check for exact string match, or wildcard match (star in last position)
    # - both args must be cleaned by cleanup_deriv_path() already
    # - this is only used in hsm.py for approving {address, msg_sign, xpub}
    # - will accept any path, if 'any' in patterns
    if 'any' in patterns:
        return True
    elif path == "*":
        return False
    elif path == "any":
        return False

    for pat in patterns:
        if pat == path:
            return True

        if pat.endswith('/*') or pat.endswith('/*h'):
            if pat[-1] == 'h' and path[-1] != 'h': continue     # mismatch: want hard, it's not
            if pat[-1] == '*' and path[-1] == 'h': continue     # mismatch: want unhard, it is

            # same hardness so check up to last component of path
            if pat.split('/')[:-1] == path.split('/')[:-1]:
                return True

    return False

class DecodeStreamer:
    def __init__(self):
        self.runt = bytearray()

    def more(self, buf):
        # Generator:
        # - accumulate into mod-N groups
        # - strip whitespace
        for ch in buf:
            if chr(ch).isspace(): continue
            self.runt.append(ch)
            if len(self.runt) == 128*self.mod:
                yield self.a2b(self.runt)
                self.runt = bytearray()

        here = len(self.runt) - (len(self.runt) % self.mod)
        if here:
            yield self.a2b(self.runt[0:here])
            self.runt = self.runt[here:]

class HexStreamer(DecodeStreamer):
    # be a generator that converts hex digits into binary
    # NOTE: mpy a2b_hex doesn't care about unicode vs bytes
    mod = 2
    def a2b(self, x):
        return a2b_hex(x)

class Base64Streamer(DecodeStreamer):
    # be a generator that converts Base64 into binary
    mod = 4
    def a2b(self, x):
        return a2b_base64(x)


def check_firmware_hdr(hdr, binary_size):
    # Check basics of new firmware being loaded. Return text of error msg if any.
    # - basic checks only: for confused customers, not attackers.
    # - hdr must be a bytearray(FW_HEADER_SIZE+more)

    from sigheader import FW_HEADER_SIZE, FW_HEADER_MAGIC, FWH_PY_FORMAT
    from sigheader import MK_1_OK, MK_2_OK, MK_3_OK, MK_4_OK, MK_Q1_OK
    from ustruct import unpack_from
    from version import hw_label
    import callgate

    try:
        assert len(hdr) >= FW_HEADER_SIZE

        magic_value, timestamp, version_string, pk, fw_size, install_flags, hw_compat = \
                        unpack_from(FWH_PY_FORMAT, hdr)[0:7]

        assert magic_value == FW_HEADER_MAGIC, 'bad magic'
        assert fw_size == binary_size or fw_size == (binary_size-128), 'size problem'

    except Exception as exc:
        return "That does not look like a firmware " \
                    "file we would want to use: %s" % exc

    if hw_compat != 0:
        # check this hardware is compatible
        ok = False
        if hw_label == 'mk1':
            ok = (hw_compat & MK_1_OK)
        elif hw_label == 'mk2':
            ok = (hw_compat & MK_2_OK)
        elif hw_label == 'mk3':
            ok = (hw_compat & MK_3_OK)
        elif hw_label == 'mk4':
            ok = (hw_compat & MK_4_OK)
        elif hw_label == 'q1':
            ok = (hw_compat & MK_Q1_OK)
        
        if not ok:
            return "That firmware doesn't support this version of Coldcard hardware (%s)."%hw_label

    water = callgate.get_highwater()
    if water[0] and timestamp < water:
        return "That downgrade is not supported."

    return None


def clean_shutdown(style=0):
    # wipe SPI flash and shutdown (wiping main memory)
    # - mk4: SPI flash not used, but NFC may hold data (PSRAM cleared by bootrom)
    # - bootrom wipes every byte of SRAM, so no need to repeat here
    import callgate, version, uasyncio

    # save if anything pending
    from glob import settings
    settings.save_if_dirty()

    try:
        from glob import dis, NFC
        dis.fullscreen("Cleanup...")

        if NFC:
            uasyncio.run(NFC.wipe(True))
                
    except: pass

    # on Q1, must power down because annoying to do power cycle
    # when micro is stopped
    if style != 2 and version.has_battery:
        style = 3

    callgate.show_logout(style)

def call_later_ms(delay, cb, *args, **kws):
    import uasyncio

    async def doit():
        await uasyncio.sleep_ms(delay)
        await cb(*args, **kws)
        
    uasyncio.create_task(doit())

def txtlen(s):
    # width of string in chars, accounting for
    # double-wide characters which happen on Q.
    rv = len(s)

    if DOUBLE_WIDE:
        rv += sum(1 for ch in s if ch in DOUBLE_WIDE)

    return rv

def word_wrap(ln, w):
    # Generate the lines needed to wrap one line into X "width"-long lines.
    #  - tests in testing/test_unit.py

    if txtlen(ln) <= w:
        yield ln
        return

    while ln:

        # find a space in (width) first part of remainder
        sp = ln.rfind(' ', 0, w-1)

        if sp == -1:
            # bad-break the line
            sp = min(txtlen(ln), w)
            nsp = sp
            if ln[nsp:nsp+1] == ' ':
                nsp += 1
        else:
            # split on found space
            nsp = sp+1

        left = ln[0:sp]
        ln = ln[nsp:]

        if txtlen(left) + 1 + txtlen(ln) <= w:
            # not clear when this would happen? final bit??
            left = left + ' ' + ln
            ln = ''

        yield left

def parse_addr_fmt_str(addr_fmt):
    # accepts strings and also integers if already parsed
    from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH

    if addr_fmt in [AF_P2WPKH_P2SH, AF_P2WPKH, AF_CLASSIC]:
        return addr_fmt

    addr_fmt = addr_fmt.lower()
    if addr_fmt in ("p2sh-p2wpkh", "p2wpkh-p2sh"):
        return AF_P2WPKH_P2SH
    elif addr_fmt == "p2pkh":
        return AF_CLASSIC
    elif addr_fmt == "p2wpkh":
        return AF_P2WPKH
    else:
        raise ValueError("Invalid address format: '%s'\n\n"
                           "Choose from p2pkh, p2wpkh, p2sh-p2wpkh." % addr_fmt)

def parse_extended_key(ln, private=False):
    # read an xpub/ypub/etc and return BIP-32 node and what chain it's on.
    # - can handle any garbage line
    # - returns (node, chain, addr_fmt)
    # - people are using SLIP132 so we need this
    node, chain, addr_fmt = None, None, None
    if ln is None:
        return node, chain, addr_fmt

    ln = ln.strip()
    if private:
        rgx = r'.prv[A-Za-z0-9]+'
    else:
        rgx = r'.pub[A-Za-z0-9]+'

    pat = ure.compile(rgx)
    found = pat.search(ln)
    # serialize, and note version code
    try:
        node, chain, addr_fmt, is_private = chains.slip32_deserialize(found.group(0))
    except:
        pass

    return node, chain, addr_fmt

def chunk_writer(fd, body):
    from glob import dis
    dis.fullscreen("Saving...")
    body_len = len(body)
    chunk = body_len // 10
    for idx, i in enumerate(range(0, body_len, chunk)):
        fd.write(body[i:i + chunk])
        dis.progress_bar_show(idx / 10)
    dis.progress_bar_show(1)


def addr_fmt_label(addr_fmt):
    return {
        AF_CLASSIC: "Classic P2PKH",
        AF_P2WPKH_P2SH: "P2SH-Segwit",
        AF_P2WPKH: "Segwit P2WPKH"
    }[addr_fmt]


def pad_raw_secret(raw_sec_str):
    # Chip can hold 72-bytes as a secret
    # every secret has 0th byte as marker
    # then secret and padded to zero to AE_SECRET_LEN
    from pincodes import AE_SECRET_LEN

    raw = bytearray(AE_SECRET_LEN)
    if len(raw_sec_str) % 2:
        raw_sec_str += '0'
    x = a2b_hex(raw_sec_str)
    raw[0:len(x)] = x
    return raw

def seconds2human_readable(s):
    days = s // (3600 * 24)
    hours = s % (3600 * 24) // 3600
    minutes = (s % 3600) // 60
    seconds = (s % 3600) % 60
    msg = []
    if days:
        msg.append("%dd" % days)
    if hours:
        msg.append("%dh" % hours)
    if minutes:
        msg.append("%dm" % minutes)
    if seconds:
        msg.append("%ds" % seconds)

    return " ".join(msg)

def datetime_from_timestamp(ts):
    gm_t = time.gmtime(0)
    if gm_t[0] == 1970:
        # unix
        epoch_sub = 0
    elif gm_t[0] == 2000:
        # stm32
        epoch_sub = 946684800
    else:
        assert False

    return time.gmtime(ts - epoch_sub)

def datetime_to_str(dt, fmt="%d-%02d-%02d %02d:%02d:%02d"):
    y, mo, d, h, mi, s = dt[:6]
    dts = fmt % (y, mo, d, h, mi, s)
    return dts + " UTC"

def url_decode(u):
    # expand control chars from %XX and '+'
    # - equiv to urllib.parse.unquote_plus
    # - ure.sub is missing, so not being clever here.
    # - give up on syntax errors, and return unchanged
    import ure

    u = u.replace('+', ' ')
    while 1:
        pos = u.find('%')
        if pos < 0: break

        try:
            ch = chr(int(u[pos+1:pos+3], 16))
            assert ch != '\0'
        except:
            return u

        u = u[0:pos] + ch + u[pos+3:]

    return u

def decode_bip21_text(got):
    # Assume text is a BIP-21 payment address (url), with amount, description
    # and url protocol prefix ... all optional except the address.
    # - also will detect correctly encoded & checksummed xpubs

    proto, args, addr = None, None, None

    # remove URL protocol: if present
    if ':' in got:
        proto, got = got.split(':', 1)

    # looks like BIP-21 payment URL
    if '?' in got:
        addr, args = got.split('?', 1)

        # full URL decode here, but assuming no repeated keys
        parts = args.split('&')
        args = dict()
        for p in parts:
            k, v = p.split('=', 1)
            args[k] = url_decode(v)

    # assume it's an bare address for now
    if not addr:
        addr = got

    # old school
    try:
        raw = ngu.codecs.b58_decode(addr)

        # it's valid base58
        # an address, P2PKH or xpub (xprv checked above)
        if addr[1:4] == 'pub':
            return 'xpub', (addr,)

        return 'addr', (proto, addr, args)
    except:
        pass

    # new school: bech32 or bech32m
    try:
        hrp, version, data = ngu.codecs.segwit_decode(addr)
        return 'addr', (proto, addr.lower(), args)
    except:
        pass

    raise ValueError('not bip-21')

def censor_address(addr):
    # We don't like to show the user multisig addresses because we cannot be certain
    # they are valid and could actually be signed. And yet, dont blank too many
    # spots or else an attacker could grind out a suitable replacement.
    return addr[0:12] + '___' + addr[12+3:]

# EOF
