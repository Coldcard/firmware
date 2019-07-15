
def get_mpy_version():
    return '2019-07-03', '2.1.1', '180711195308'

def is_factory_mode():
    # pretend signed w/ dev key and allow debug
    import sys
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
