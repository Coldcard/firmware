# Freeze everything in this list.
# - not optimized because we need asserts to work
# - for specific boards, see manifest_{mk4,q1}.py and manifest_q1.py
freeze_as_mpy('', [
	'actions.py',
	'address_explorer.py',
	'auth.py',
    'msgsign.py',
	'backups.py',
	'bsms.py',
	'callgate.py',
	'chains.py',
	'choosers.py',
	'compat7z.py',
	'countdowns.py',
	'descriptor.py',
	'desc_utils.py',
	'dev_helper.py',
	'display.py',
	'drv_entro.py',
	'exceptions.py',
	'export.py',
	'files.py',
	'flow.py',
	'ftux.py',
	'glob.py',
	'history.py',
	'imptask.py',
	'login.py',
	'main.py',
	'menu.py',
	'miniscript.py',
	'multisig.py',
	'numpad.py',
	'nvstore.py',
	'opcodes.py',
	'paper.py',
	'pincodes.py',
	'precomp_tag_hash.py',
	'psbt.py',
	'pwsave.py',
	'queues.py',
	'qrs.py',
	'random.py',
	'seed.py',
	'selftest.py',
	'serializations.py',
	'sffile.py',
	'ssd1306.py',
	'stash.py',
	'usb.py',
	'utils.py',
	'ux.py',
	'version.py',
	'xor_seed.py',
	'tapsigner.py',
	'wallet.py',
	'ownership.py',
	'ccc.py',
	'web2fa.py',
	'psram.py',
	'mk4.py',
	'vdisk.py',
	'nfc.py',
	'ndef.py',
	'trick_pins.py',
], opt=0)

# Optimize data-like files, since no need to debug them.
freeze_as_mpy('', [
	'sigheader.py',
	'public_constants.py',
	'charcodes.py',
], opt=3)

# Maybe include test code.
import os
if int(os.environ.get('DEBUG_BUILD', 0)):
    freeze_as_mpy('', [
        'h.py',
        'dev_helper.py',
        'usb_test_commands.py',
        'sim_display.py',
    ], opt=0)

include("$(MPY_DIR)/extmod/uasyncio/manifest.py")
