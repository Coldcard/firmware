import sys

def get_mpy_version():
<<<<<<< HEAD
    return '2019-07-03', '3.x.x', '180711195308'
=======
    return '2019-09-06', '2.1.3', '180711195308'
>>>>>>> master

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

has_membrane = True
hw_label = 'mk2'
has_608 = False

if  '-3' in sys.argv:
    hw_label = 'mk3'
    has_608 = True

