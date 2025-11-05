# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# compat7z.py
#
# Implement a bare-bones 7z encrypted file read/writer. Does not do compression, but
# always does AES-256. Not really expecting to be able to read any 7z file, except
# those we created ourselves.
#
import os, sys, ckcc, ngu
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from ubinascii import crc32
from ustruct import unpack, pack, calcsize
from ucollections import namedtuple
from uhashlib import sha256
from uio import BytesIO
        
def masked_crc(bits):
    return crc32(bits) & 0xffffffff

def urandom(l):
    rv = bytearray(l)
    ckcc.rng_bytes(rv)
    return rv

def encode_utf_16_le(s):
    # emulate: str.encode('utf-16-le')
    # by assuming ascii values
    if isinstance(s, str):
        s = s.encode()
    return bytes((s[i//2] if i%2==0 else 0) for i in range(len(s)*2))

def decode_utf_16_le(s):
    # emulate: bytes.dencode('utf-16-le')
    # by assuming simple ascii values
    if isinstance(s, str):
        s = s.encode()
    return bytes(s[i] for i in range(0, len(s), 2)).decode()

'''
  Size of encoding sequence depends from first byte:
  First_Byte  Extra_Bytes        Value
  (binary)   
  0xxxxxxx               : ( xxxxxxx           )
  10xxxxxx    BYTE y[1]  : (  xxxxxx << (8 * 1)) + y
  110xxxxx    BYTE y[2]  : (   xxxxx << (8 * 2)) + y
  ...
  1111110x    BYTE y[6]  : (       x << (8 * 6)) + y
  11111110    BYTE y[7]  :                         y
  11111111    BYTE y[8]  :                         y
'''

def read_var64(f):
    '''
        Decode their silly 64-bit encoding.
    '''
    first = ord(f.read(1))
    if first < 128:
        return first
    elif first == 0xfe or first == 0xff:
        return unpack("<Q", f.read(8))[0]
    else:
        pos = bin(first)[2:].find('10') + 1
        assert 1 <= pos <= 6
        tmp = f.read(pos)
        tmp += '\x00' * (8-pos)
        assert len(tmp) == 8
        y = unpack("<Q", tmp)[0]
        x = first & (0xEF >> pos)
        return (x << pos) + y
    
def write_var64(n):
    # write their funky 64-bit variable-width unsigned number.
    # up to 64 bits of uint, but typically just single bytes
    # cheating a little here, these aren't optimal
    if n < 127:
        return chr(n)
    if n < 65536:
        return b'\xc0' + pack('<H', n)
    if n < 2**32:
        return b'\xf0' + pack('<L', n)
    else:
        return b'\xff' + pack('<Q', n)

''' test code only
def test_var64():
    # test possible edges only
    for i in range(0,10) + range(125,130) + range(250, 260) \
                + range((2**16)-20, (2**16)+20) \
                + range((2**32)-20, (2**32)+20) \
                + range((2**40)-20, (2**40)+20) \
                + range((2**64)-20, (2**64)) \
        :
        f = StringIO(write_var64(i))
        assert read_var64(f) == i, '%d != %s' % (i, b2a_hex(f.getvalue()))
'''
    
def check_file_headers(f):
    # read the file-header and the "first" other header
    # assume f is seekable
    fh = FileHeader.read(f)

    if not fh.has_good_magic:
        raise ValueError("Bad magic bytes")

    # read only first header
    sh = SectionHeader.read(f)

    if sh.actual_crc() != fh.crc:
        #print('act=%r expect=%r bits=%r' % (sh.actual_crc(), fh.crc, fh.bits))
        raise ValueError("Second header has wrong CRC")

    if sh.size > 10000:
        raise ValueError("Second header too big")

    # capture this spot
    # TODO 'data_start' unused
    data_start = f.tell()       # expect 0x20

    try:
        f.seek(sh.offset, 1)
        th = f.read(sh.size)
        if len(th) != sh.size:
            raise IndexError("Truncated file?")

        # Look for properties about compression. this could be 
        # faked-out but good enough for now
        if b'\x24\x06\xf1\x07\x01' not in th:
            raise RuntimeError("Not marked as AES+SHA encrypted?")
    except Exception as e:
        raise ValueError("Confused file? %s" % e.message)

    if masked_crc(th) != sh.crc:
        raise ValueError("Trailing header has wrong CRC")

    # Not clear if there can be more headers, but assume only one for now.

    # success; restore file pointer, just in case
    f.seek(0)

    return
    

class FileHeader(object):
    def __init__(self):
        self.magic = b"7z\xbc\xaf'\x1c"
        self.major = 0
        self.minor = 3
        self.crc = 0        # actually the CRC of the next header

    def has_good_magic(self):
        if self.magic != b"7z\xbc\xaf'\x1c":
            return False
        if self.major != 0:
            return False
        if self.minor < 3:
            return False
        return True

    @classmethod
    def read(cls, f):
        fmt = '<6sBBL'
        bits = f.read(calcsize(fmt))

        self = cls()
        self.bits = bits
        self.magic, self.major, self.minor, self.crc = unpack(fmt, bits)

        return self

    def write(self):
        self.bits = self.magic + pack('<BBL', self.major, self.minor, self.crc)
        return self.bits 

    def actual_crc(self):
        return masked_crc(self.bits)

        

class SectionHeader(namedtuple('SectionHeader', ['offset', 'size', 'crc' ])):
    @classmethod
    def read(cls, f):
        # read only next one; ftell has to be on first byte already
        fmt = '<QQL'

        sz = calcsize(fmt)
        bits = f.read(sz)
        if not bits:
            return

        rv = cls(*unpack(fmt, bits))
        rv.bits = bits

        return rv

    @classmethod
    def read_iter(cls, f, expect_crc=None):
        # read only next one; ftell has to be on first byte already
        rv = cls.read(f)

        if expect_crc is not None:
            assert rv           # read past end
            assert masked_crc(rv.bits) == expect_crc

        section = f.read(rv.offset)
        hdr = f.read(rv.size)

        yield rv, hdr, section

    def write(self):
        return pack('<QQL', self.offset, self.size, self.crc)

    def actual_crc(self):
        return masked_crc(self.bits)

class Builder(object):
    def __init__(self, password=None, salt_len=16, iv_len=16, rounds_pow=13, progress_fcn=None):
        self.rounds_pow = rounds_pow            # standard is 19, 16 and 17 work fine

        if password:
            self.salt = urandom(salt_len)
            self.iv = urandom(iv_len)

            self.key = self.calculate_key(password, progress_fcn)

        self.unpacked_size = 0
        self.body = b''
        self.body_len = 0
        self.aes = None
        self.pt_crc = 0         # == crc32('')
        self.ct_crc = 0         # == crc32('')
        self.padding = None

    @classmethod
    def from_external(cls, **kws):
        # constructor that takes all the data we'd need.
        self = cls()
        for k,v in kws.items():
            setattr(self, k, v)

        assert self.body_len
        assert self.body_len % 16 == 0
        assert self.unpacked_size
        assert self.salt and self.iv

        return self

    def read_file(self, fd, password, max_size, progress_fcn=None):
        # read a file we wrote; unlikely to work on anything else.
        # assuming single file contained inside
        fhdr = FileHeader.read(fd)
        assert fhdr.has_good_magic()

        for shdr, meta, body in SectionHeader.read_iter(fd):
            # read out salt data, fname, sizes
            fname, body_size, unpacked_size, expect_crc = self.parse_section_hdr(meta)

            assert len(body) == body_size
            assert unpacked_size <= max_size, 'too big'
            assert len(body) <= unpacked_size+16, 'too big, encoded'
            assert len(body) % 16 == 0, 'not blocked'

            # figure out key to be used
            key = self.calculate_key(password, progress_fcn)

            aes = ngu.aes.CBC(False, key, self.iv)

            out = b''
            for blk in range(0, len(body), 16):
                out += aes.cipher(body[blk:blk+16])

            aes.blank()

            # trim padding, check CRC
            out = out[0:unpacked_size]
            if masked_crc(out) != expect_crc:
                raise ValueError("Wrong password given, or damaged file.")

            # done. return contents
            return fname, out
            
    def verify_file_crc(self, fd, max_size, expected_sections=3):
        # Read each section, and check CRC of headers, return list of files & sizes.
        fhdr = FileHeader.read(fd)
        assert fhdr.has_good_magic()

        expect_crc = fhdr.crc
        files = []
        for shdr, meta, body in SectionHeader.read_iter(fd, expect_crc=expect_crc):
            # read out salt data, fname, sizes
            # note: unpacked_size, expect_crc are of the plaintext (so w/o key, we can't confirm)
            fname, body_size, unpacked_size, expect_crc = self.parse_section_hdr(meta)

            assert len(body) == body_size
            assert unpacked_size <= max_size        # 'too big'
            assert len(body) <= unpacked_size+16    # 'too big, encoded'
            assert len(body) % 16 == 0              # 'not blocked'

            #print("Section ok: '%s' of %d bytes =>  %r" % (fname, unpacked_size, shdr))

            files.append((fname, unpacked_size))

        # should be at end of file now.
        assert not fd.read(10)

        return files

    def add_data(self, raw):
        if not self.aes:
            # do this late, so easier to test w/ known values.
            self.aes = ngu.aes.CBC(True, self.key, self.iv)

        here = len(raw)
        self.pt_crc = crc32(raw, self.pt_crc)

        padded_len = (here + 15) & ~15
        if padded_len != here:
            if self.padding is not None:
                raise ValueError()          # "can't do less than a block except at end"
            self.padding =  (padded_len - here)
            raw += bytes(self.padding)
        self.unpacked_size += here

        assert len(raw) % 16 == 0
        self.body += self.aes.cipher(raw)


    def calculate_key(self, password, progress_fcn=None):
        # do the expected key-derivation
        # emulate CKeyInfo::CalculateDigest in p7zip_9.38.1/CPP/7zip/Crypto/7zAes.cpp
        rounds = 1 << self.rounds_pow

        password = encode_utf_16_le(password)

        result = sha256()

        for i in range(rounds):
            result.update(self.salt)
            result.update(password)
            temp = pack('<Q', i)
            result.update(temp)
            if i % 1000 == 0 and progress_fcn:
                progress_fcn(i/rounds)
            
        return result.digest()

    def render_hdr(self, fname):
        # make the "header" that's really a trailer, which has all the meta data
        # for the records. Not adding anything we don't need.
        def BB(n):
            return a2b_hex(n.replace(' ',''))

        if self.body and not self.body_len:
            self.body_len = len(self.body)

        rv = BB('01 04 06 00 01 09')
            # 01 - kHeader
            # 04 - kMainStreamsInfo
            # 06 - kPackInfo
            # 	00 		PackPos (UINT64) = 0
            # 	01 		NumPackStreams = 1
            # 	09 - kSize
        rv += write_var64(self.body_len)
        rv += BB('00')       # kEnd

        '''
        07 - kUnPackInfo
            0b - kFolder
             01	 	NumFolders(UINT64) =1
             00   	External(byte) = 0 = false (ie. data is here)
            01 = NumCoders
            { foreach folder (1) }
                24 - bitmask:
                          5:  There Are Attributes
                          4:  Is Complex Coder
                          0:3 CodecIdSize
                      = 4 bytes of codec id + "There Are Attributes"
        '''
        rv += BB('07 0b 01 00 01 24')
        rv += BB('06 f1 07 01')      		# = AES-256 + SHA-256
    
        props = self.render_crypto_props()
        rv += write_var64(len(props))
        rv += props

		# 01 - InIndex
		# 00 - OutIndex
        rv += BB('01 00')

        rv += BB('0c ') + write_var64(self.unpacked_size) + BB(' 00') 

        if 0:
            rv += BB('08 00')       # empty kSubStreamsInfo
        else:
            # kSubStreamsInfo with kCRC
            rv += BB('08 0a 01 ') + pack('<L', self.pt_crc & 0xffffffff) + BB('00')       

        rv += BB('00')       # kEnd 

        '''
            05 - kFilesInfo
                01 - NumFiles = 1

                11 - kName
                    13 - size of property = 19 bytes
                    00 - external (bool) False
        '''
        fname = encode_utf_16_le(fname + u'\x00')
        rv += BB('05 01 11') + write_var64(len(fname) + 1) + BB('00') + fname

        rv += BB('00')       # kEnd 
        rv += BB('00')       # kEnd 

        return rv

    def parse_section_hdr(self, hdr):
        # Read file name, unpacked size and crypto values  out of a section header,
        # but assume we wrote it and don't be flexible or compliant or correct to standard.
        def BB(n):
            return a2b_hex(n.replace(' ',''))

        fh = BytesIO(hdr)

        def patmatch(pattern, where):
            # search forward, return file obj right after pattern
            pat = BB(pattern)
            pos = where.find(pat)
            if pos == -1:
                raise KeyError(pattern)
            return BytesIO(where[pos+len(pat):])

        # find length part
        rv = patmatch('01 04 06 00 01 09', hdr)
        body_size = read_var64(rv)

        # skip forward to crypto details
        rv = patmatch('07 0b 01 00 01 24 ' + '06 f1 07 01', rv.getvalue())

        crypto_props_len = read_var64(rv)
        start_pos = rv.seek(0, 1)       # .tell() is missing

        first, second = rv.read(2)
        self.rounds_pow = first & 0x3f

        assert first & 0xc0 == 0xc0, "require salt+iv"

        salt_len = ((second >> 4) & 0xf) + 1
        iv_len = (second & 0xf) + 1

        assert salt_len >= 16
        assert iv_len >= 16

        self.salt = rv.read(salt_len)
        self.iv = rv.read(iv_len)

        end_pos = rv.seek(0, 1)       # .tell() is missing
        assert end_pos - start_pos == crypto_props_len, (end_pos, start_pos, crypto_props_len)

        rv = patmatch('01 00 0c', rv.getvalue())
        unpacked_size = read_var64(rv)
        assert rv.read(1) == b'\0'

        rv = patmatch('08 0a 01', rv.getvalue())
        expect_crc = unpack('<L', rv.read(4))[0]
        assert rv.read(1) == b'\0'

        rv = patmatch('05 01 11', rv.getvalue())
        fname_len = read_var64(rv) - 1
        assert rv.read(1) == b'\0'

        # remove also a null at end of string
        fname = decode_utf_16_le(rv.read(fname_len))[:-1]

        assert rv.read(2) == b'\0\0'

        return fname, body_size, unpacked_size, expect_crc
        

    def render_crypto_props(self):
        # render 2 bytes of header, then IV and or salt.
        first = self.rounds_pow & 0x3f
        if self.salt: first |= 0x80
        if self.iv: first |= 0x40

        assert len(self.salt) <= 16
        assert len(self.iv) <= 16

        second = ((len(self.salt)-1 if self.salt else 0) << 4) \
                        | (len(self.iv)-1 if self.iv else 0)

        return bytes([first, second]) + self.salt + self.iv

    def save(self, fname='backup.txt'):
        # Render two final 7z file parts: the header and footer.
        # Caller must put self.body inbetween them.
        sh = self.render_hdr(fname)
        sect = SectionHeader(size=len(sh),
                                offset=self.body_len,
                                crc=masked_crc(sh))

        ff = FileHeader()
        ff.crc = masked_crc(sect.write())

        return ff.write() + sect.write(), sh
        

''' working test code, but not needed in field...

def test_aes():
    t = Builder(b'')
    # key is "test" with no salt.
    t.key = a2b_hex('886660203c30b116ac07bc8d24066697f35e476e7f07d6118ea9f27fbfb5d27b')
    # iv from file "example-packed.7z"
    t.iv = a2b_hex('ca9f7eae1b7261630000000000000000')
    t.add_data(b'Hello\n')
    assert t.body == a2b_hex('56c1d8417e533c947bc6dd472b4e073f')
    print("encrypt works")

def test_keybuild():
    import pylzma
    t = Builder(b'test', salt_len=0)
    assert t.rounds_pow == 19, "test data assumes 19"
    assert t.key == a2b_hex('886660203c30b116ac07bc8d24066697f35e476e7f07d6118ea9f27fbfb5d27b')
    assert t.key == t.calculate_key()
    
    t.salt = 'abcdef'
    t.rounds_pow = 16
    assert pylzma.calculate_key(t.password, cycles=t.rounds_pow, salt=t.salt) \
                == t.calculate_key()
    print("key deriv. works")
    
def test_buildone():
    t = Builder(b'test')
    t.add_data(b'a'*16)
    t.add_data(b'a'*16*8)
    t.add_data(b'Hello 123\n')

    hdr, footer = t.save()
    with open('out.7z', 'wb') as f:
        f.write(hdr)
        f.write(t.body)
        f.write(footer)
    print("wrote file")

def test_check_file_headers():
    import glob
    files = glob.glob('*.7z') + glob.glob('*/*.7z') \
                + glob.glob('enc7z/p7zip_9.38.1/check/test/*.7z')
    for fn in files:
        check_file_headers(file(fn, 'rb'))
        print('%s: OK' % fn)

if __name__ == '__main__':
    test_aes()
    test_keybuild()
    test_var64()
    test_buildone()
    #test_check_file_headers()
'''

# EOF
