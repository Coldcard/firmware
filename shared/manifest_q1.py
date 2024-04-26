# Q1/Mk4 only files; would not be needed on Mk3 or earlier.
freeze_as_mpy('', [
	'psram.py',
	'mk4.py',
	'q1.py',
	'keyboard.py',
	'scanner.py',
	'bbqr.py',
    'decoders.py',
	'lcd_display.py',
	'st7788.py',
	'gpu.py',
	'vdisk.py',
	'nfc.py',
	'ndef.py',
	'trick_pins.py',
	'ux_q1.py',
	'battery.py',
	'notes.py',
	'calc.py',
], opt=0)

# Optimize data-like files, since no need to debug them.
freeze_as_mpy('', [
	'graphics_q1.py',
	'font_iosevka.py',
	'gpu_binary.py',        # remove someday?
], opt=3)

