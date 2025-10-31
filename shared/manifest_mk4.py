# Mk4 only files; would not be needed on Mk3 or earlier.
freeze_as_mpy('', [
	'hsm.py',
	'hsm_ux.py',
	'mempad.py',
	'ssd1306.py',
	'users.py',
	'ux_mk4.py'
], opt=0)

# Optimize data-like files, since no need to debug them.
freeze_as_mpy('', [
	'graphics_mk4.py',
	'zevvpeep.py',
], opt=3)
