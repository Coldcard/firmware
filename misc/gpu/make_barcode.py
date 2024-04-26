#!/usr/bin/env python3
#
# Render a little barcode we need for selftest process.
#
# - packed bytes
#
import barcode
from io import BytesIO
from barcode import Code128
from barcode.writer import ImageWriter


class Packer(barcode.writer.BaseWriter):
    # api in <../../ENV/lib/python3.10/site-packages/barcode/writer.py>
    def __init__(self):
        super().__init__(initialize=self.do_init,
                            paint_module=self.paint, paint_text=self.do_text, finish=self.do_fin)

    def do_init(self, code):
        # the answer I want is given to init function: binary for black/white sections
        assert len(code) == 1, 'not a list?'
        code = code[0]

        if len(code) % 2:
            code += '0'
        while (len(code) % 8) != 0:
            code = f'0{code}0'

        #code = code.replace('0', '00').replace('1', '11')      # double it up
        code = code.replace('0', '000').replace('1', '111')     # 3X
        #code = code.replace('0', '0000').replace('1', '1111')  # 4X

        # pad to 320 pixels (div 8) (centered)
        while len(code) < 320:
            code = f'0000{code}0000'

        # convert to bytes
        self.result = int(code, 2).to_bytes(len(code)//8, 'big')

    def do_text(self, *unused):
        pass

    def paint(self, xpos, ypos, width, color):
        #print(f'paint: pos={xpos},{ypos} w={width} c={color}')
        pass

    def do_fin(self):
        return self.result

def doit(ofile='barcode.h'):

    # contents of barcode
    if 0:
        # works, but overkill and reads better if simpler
        version = None
        with open('version.h') as fd:
            for ln in fd:
                if 'RELEASE_VERSION' in ln:
                    version = eval(ln.split()[-1])
                    break
        assert version
        msg = f'GPU={version}'

    msg = f'GPU'
    bc = Code128(msg, writer=Packer())
    rv = bc.render()

    #bc2 = Code128(msg, writer=ImageWriter())
    #bc2.write('check.png')
    
    #print(f'Result: {rv.hex()} len={len(rv)}')

    assert len(rv) * 8 <= 320, 'too wide to fit on screen'
    assert len(rv) == 40, 'expected 320 pixels'

    enc = rv.hex(' ', 1).replace(' ', ', 0x')

    with open(ofile, 'wt') as fd:
        fd.write(f'''// autogen file, see make_barcode.py

// in python: {repr(rv)}
static const uint8_t test_barcode[{len(rv)}] = {{
    0x{enc}
}};

// EOF''')

    print(f"Updated: {ofile}")

if __name__ == '__main__':
    doit()

# EOF
