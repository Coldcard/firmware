# Q1 only files; would not be needed on Mk4
freeze_as_mpy('', [
	'battery.py',
	'bbqr.py',
	'calc.py',
	'decoders.py',
	'gpu.py',
	'keyboard.py',
	'lcd_display.py',
	'notes.py',
	'q1.py',
	'scanner.py',
	'st7788.py',
	'teleport.py',
	'ux_q1.py'
], opt=0)

# Optimize data-like files, since no need to debug them.
freeze_as_mpy('', [
	'font_iosevka.py',
	'gpu_binary.py',        # remove someday?
	'graphics_q1.py',
], opt=3)

