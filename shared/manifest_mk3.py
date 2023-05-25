# Mk3 and earlier only files; would not be needed on Mk4 or later
freeze_as_mpy('', [
	'mempad.py',
	'ssd1306.py',
	'sflash.py',
], opt=0)

# Optimize data-like files, since no need to debug them.
freeze_as_mpy('', [
	'graphics.py',
	'zevvpeep.py',
], opt=3)

