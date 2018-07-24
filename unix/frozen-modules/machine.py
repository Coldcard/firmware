from mock import Mock

Pin = Mock
Pin.ALT = None
Pin.PULL_NONE = None
Pin.AF8_UART4 = None

SPI = Mock

UART = Mock
UART.OUT = None

def _flush_data():
    try:
        from main import settings
        settings.save()
    except: pass

def bootloader():
    print("\nEnter bootloader (DFU)\n")
    _flush_data()
    raise SystemExit

def soft_reset():
    print("\nDo a soft reset\n")
    _flush_data()
    raise SystemExit

def reset():
    print("\nDo a hard reset\n")
    _flush_data()
    raise SystemExit

def unique_id():
    # 12 bytes
    return b'sim'*4
