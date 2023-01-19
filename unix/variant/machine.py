from mock import Mock

class Pin:
    def __init__(self, name, *a, **kw):
        self.name = name
        self.cur_value = 0

    def on(self):
        self.value(1)
    def off(self):
        self.value(0)

    def value(self, n=None):
        if n is None: return self.cur_value
        self.cur_value = int(n)

        bm = 0
        if self.name == 'SD_ACTIVE':
            bm = 0x02
        elif self.name == 'USB_ACTIVE':
            bm = 0x04

        if bm:
            from ckcc import led_pipe
            led_pipe.write(bytes([(bm << 4) | (bm if n else 0)]))

    def pin(self):
        # ? pin number
        return 99

    def irq(self, *a, **k):
        # hack in the keyboard system
        if self.name == 'LCD_TEAR':
            from touch import Touch
            Touch()
        pass

    ALT = None
    PULL_NONE = None
    PULL_UP = None
    OUT_OD = None
    OUT = None
    AF8_UART4 = None
    IN = None
    IRQ_FALLING = 1
    IRQ_RISING = 2

SPI = Mock
UART = Mock
UART.OUT = None

def _flush_data():
    try:
        from glob import settings
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
