import sys

def get_mpy_version():
    return '2019-09-30', '3.x.x', '180711195308'

def is_factory_mode():
    # pretend signed w/ dev key and allow debug
    return bool('-f' in sys.argv)

def is_devmode():
    return True

def is_fresh_version():
    return False

def serial_number():
    return 'F1'*6

def get_header_value(fld_name):
    if fld_name == 'timestamp':
        return b'\x18\x07\x11\x19S\x08\x00\x00'
    return 0

# default is latest hardware
hw_label = 'mk3'
has_608 = True
has_membrane = True

if  '--mk2' in sys.argv:
    hw_label = 'mk2'
    has_608 = False

if  '--mk1' in sys.argv:
    hw_label = 'mk1'
    has_608 = False
    has_membrane = False

