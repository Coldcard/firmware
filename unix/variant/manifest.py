freeze_as_mpy('', [
	'aes256ctr.py',
	'bare_metal.py',
	'ckcc.py',
	'ffilib.py',
	'machine.py',
	'mock.py',
	'os.py',
	'pyb.py',
	'sflash.py',
	'sim_mk4.py',
	'sim_nfc.py',
	'sim_psram.py',
	'sim_quickstart.py',
	'sim_secel.py',
	'sim_se2.py',
	'sim_settings.py',
	'sim_vdisk.py',
	'sram2.py',
	'ssd1306.py',
	'stm.py',
	'struct.py',
	'touch.py',
	'version.py',
	'zevvpeep.py',
], opt=0)
#include("../../shared/manifest_mk4.py")
include("$(MPY_DIR)/extmod/uasyncio/manifest.py")

