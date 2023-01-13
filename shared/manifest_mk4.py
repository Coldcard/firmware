# Mk4 only files; would not be needed on Mk3 or earlier.
freeze_as_mpy('', [
	'ssd1306.py',
	'mempad.py',
	'psram.py',
	'mk4.py',
	'vdisk.py',
	'nfc.py',
	'ndef.py',
	'trick_pins.py',
], opt=0)

freeze_as_mpy('', [
	'graphics_mk4.py',
], opt=3)