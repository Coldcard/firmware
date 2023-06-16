import sys

def decode_firmware_header(hdr):
    from sigheader import FWH_PY_FORMAT
    import ustruct

    magic_value, timestamp, version_string = ustruct.unpack_from(FWH_PY_FORMAT, hdr)[0:3]

    parts = ['%02x'%i for i in timestamp]
    date = '20' + '-'.join(parts[0:3])

    vers = bytes(version_string).rstrip(b'\0').decode()

    return date, vers, ''.join(parts[:-2])

def get_mpy_version():
    return '2023-02-31', '5.x.x', '230231195308'

# pretend signed w/ dev key and allow debug
is_factory_mode = bool('-f' in sys.argv)

is_devmode = True

def is_fresh_version():
    return False

def serial_number():
    return 'F1'*6

def get_header_value(fld_name):
    if fld_name == 'timestamp':
        return b'\x18\x07\x11\x19S\x08\x00\x00'
    return 0

# default is Mk4 hardware
hw_label = 'mk4'
has_608 = True
has_membrane = True
supports_hsm = True
has_se2 = True
has_psram = True
has_nfc = True
has_qr = False
num_sd_slots = 1
has_battery = False
has_qwerty = False
is_edge = False

if  '--mk1' in sys.argv:
    # doubt this works still
    hw_label = 'mk1'
    has_608 = False
    has_membrane = False
    has_se2 = False
    has_psram = False
    has_nfc = False
    supports_hsm = False

if  '--mk2' in sys.argv:
    hw_label = 'mk2'
    has_608 = False
    has_se2 = False
    has_psram = False
    has_nfc = False
    supports_hsm = False

if  '--mk3' in sys.argv:
    hw_label = 'mk3'
    has_608 = True
    has_se2 = False
    has_psram = False
    has_nfc = False
    supports_hsm = False

mk_num = int(hw_label[2:])

if '--q1' in sys.argv:
    hw_label = 'q1'
    has_qr = True
    num_sd_slots = 2
    has_battery = True
    has_qwerty = True
    supports_hsm = False

from public_constants import MAX_TXN_LEN, MAX_UPLOAD_LEN
from public_constants import MAX_TXN_LEN_MK4, MAX_UPLOAD_LEN_MK4

if has_psram:
    # enbiggen for mk4
    MAX_UPLOAD_LEN = MAX_UPLOAD_LEN_MK4 
    MAX_TXN_LEN = MAX_TXN_LEN_MK4

# EOF
