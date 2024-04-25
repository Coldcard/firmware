from mock import Mock
import version

UNSPEC = object()

class Pin:
    def __init__(self, name, *a, **kw):
        self.name = name
        self.cur_value = int(kw.get('value', 0 if version.has_qwerty else 1))
        self.value(self.cur_value)

    def on(self):
        self.value(1)
    def off(self):
        self.value(0)

    def value(self, n=None):
        if n is None:
            return self.cur_value

        self.cur_value = int(n)

        bm = 0
        # 0x01 => SE1 light, done elsewhere
        if self.name == 'SD_ACTIVE':
            bm = 0x02
        elif self.name == 'USB_ACTIVE':
            bm = 0x04
        elif self.name == 'SD_ACTIVE2':
            bm = 0x08
        elif self.name == 'NFC_ACTIVE':
            bm = 0x10

        if bm:
            from ckcc import led_pipe
            led_pipe.write(bytes([bm, (bm if n else 0)]))

    def pin(self):
        # ? pin number
        return 99

    def irq(self, *a, **k):
        # hack in the keyboard system
        if self.name == 'LCD_TEAR':
            from touch import Touch
            Touch()
        else:
            self.irq_handler = a[0]

    def simulate_irq(self):
        self.irq_handler(self)

    def __call__(self, new_val=UNSPEC):
        if new_val==UNSPEC:
            return self.cur_value
        else:
            self.value(new_val)

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
