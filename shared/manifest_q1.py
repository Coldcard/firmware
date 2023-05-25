# Q1/Mk4 only files; would not be needed on Mk3 or earlier.
freeze_as_mpy('', [
	'psram.py',
	'mk4.py',
	'q1.py',
	'keyboard.py',
	'scanner.py',
	'lcd_display.py',
	'st7788.py',
	'vdisk.py',
	'nfc.py',
	'ndef.py',
	'trick_pins.py',
], opt=0)

# Optimize data-like files, since no need to debug them.
freeze_as_mpy('', [
	'graphics.py',          # TODO remove
	'graphics_mk4.py',      # TODO remove
	'graphics_q1.py',
], opt=3)

