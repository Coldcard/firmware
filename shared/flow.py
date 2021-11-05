# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# flow.py - Menu structure
#
from menu import MenuItem, ToggleMenuItem
import version
from glob import settings

from actions import *
from choosers import *
from multisig import make_multisig_menu
from address_explorer import address_explore
from users import make_users_menu
from drv_entro import drv_entro_start
from backups import clone_start, clone_write_data
from xor_seed import xor_split_start, xor_restore_start

# Optional feature: HSM
if version.has_fatram:
    from hsm import hsm_policy_available
else:
    hsm_policy_available = lambda: False

# Optional feature: Paper Wallets
try:
    from paper import make_paper_wallet
except:
    make_paper_wallet = None


if version.mk_num >= 4:
    from trick_pins import TrickPinMenu
    trick_pin_menu = TrickPinMenu()
else:
    trick_pin_menu = None

#
# NOTE: "Always In Title Case"
#
# - try to keep harmless things as first item: so double-tap of OK does no harm

PinChangesMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Change Main PIN', f=pin_changer, arg='main'),
    MenuItem('Second Wallet', f=pin_changer, arg='secondary',
                                predicate=lambda: not version.has_608),
    MenuItem('Duress PIN', f=pin_changer, arg='duress'),
    MenuItem('Brick Me PIN', f=pin_changer, arg='brickme'),
    MenuItem('Countdown PIN', menu=countdown_pin_submenu, predicate=lambda: version.has_608),
    MenuItem('Login Now', f=login_now, arg=1),
]

# Not reachable on Mark3 hardware
if not version.has_608:
    SecondaryPinChangesMenu = [
        #         xxxxxxxxxxxxxxxx
        MenuItem('Second Wallet', f=pin_changer, arg='secondary'),
        MenuItem('Duress PIN', f=pin_changer, arg='duress'),
        MenuItem('Countdown PIN', menu=countdown_pin_submenu),
        MenuItem('Login Now', f=login_now, arg=1),
    ]

async def which_pin_menu(_1,_2, item):
    assert version.mk_num < 4
    if version.has_608:
        # mk3
        return PinChangesMenu
    else:
        # mk2 only
        from pincodes import pa
        return PinChangesMenu if not pa.is_secondary else SecondaryPinChangesMenu

def has_secrets():
    from pincodes import pa
    return not pa.is_secret_blank()

def nfc_enabled():
    from glob import NFC
    return bool(NFC)
def vdisk_enabled():
    return bool(settings.get('vdsk', 0))

HWTogglesMenu = [
    ToggleMenuItem('USB Port', 'du', ['Default On', 'Disable USB'], invert=True,
        on_change=change_usb_disable, story='''\
Blocks any data over USB port. Useful when your plan is air-gap usage.'''),
    ToggleMenuItem('Virtual Disk', 'vdsk', ['Default Off', 'Enable', 'Enable & Auto'],
        predicate=lambda: version.has_psram, on_change=change_virtdisk_enable, 
        story='''Coldcard can emulate a virtual disk drive (4MB) where new PSBT files \
can be saved. Signed PSBT files (transactions) will also be saved here. \n\
In "auto" mode, selects PSBT as soon as written.'''),
    ToggleMenuItem('NFC Sharing', 'nfc', ['Default Off', 'Enable NFC'], on_change=change_nfc_enable,
        story='''\
NFC (Near Field Communications) allows a phone to "tap" to send and receive data \
with the Coldcard.''',
        predicate=lambda: version.has_nfc),
]

# all pre-login values
LoginPrefsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Change Main PIN', f=pin_changer, arg='main'),
    MenuItem('PIN Options', predicate=lambda: not version.has_se2, menu=which_pin_menu),
    MenuItem('Trick PINs', predicate=lambda: version.has_se2, menu=trick_pin_menu),
    MenuItem('Set Nickname', f=pick_nickname),
    MenuItem('Scramble Keypad', f=pick_scramble),
    MenuItem('Kill Key', f=pick_killkey, predicate=lambda: version.has_se2),
    MenuItem('Login Countdown', chooser=countdown_chooser),
    MenuItem('Test Login Now', f=login_now, arg=1),
]

SettingsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Login Settings', menu=LoginPrefsMenu),
    MenuItem('Hardware On/Off', menu=HWTogglesMenu),
    MenuItem('Multisig Wallets', menu=make_multisig_menu),
    MenuItem('Display Units', chooser=value_resolution_chooser),
    MenuItem('Max Network Fee', chooser=max_fee_chooser),
    MenuItem('Idle Timeout', chooser=idle_timeout_chooser),
    ToggleMenuItem('Delete PSBTs', 'del', ['Default Keep', 'Delete PSBTs'],
        story='''\
PSBT files (on SDCard) will be blanked & deleted after they are used. \
The signed transaction will be named <TXID>.txn, so the file name does not leak information.

MS-DOS tools should not be able to find the PSBT data (ie. undelete), but forensic tools \
which take apart the flash chips of the SDCard may still be able to find the \
data or filenames.'''),
]

XpubExportMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Segwit (BIP-84)", f=export_xpub, arg=84),
    MenuItem("Classic (BIP-44)", f=export_xpub, arg=44),
    MenuItem("P2WPKH/P2SH (49)", f=export_xpub, arg=49),
    MenuItem("Master XPUB", f=export_xpub, arg=0),
    MenuItem("Current XFP", f=export_xpub, arg=-1),
]

WalletExportMenu = [  
    #         xxxxxxxxxxxxxxxx (alphabetical ordering)
    MenuItem("Bitcoin Core", f=bitcoin_core_skeleton),
    MenuItem("Electrum Wallet", f=electrum_skeleton),
    MenuItem("Wasabi Wallet", f=wasabi_skeleton),
    MenuItem("Unchained Capital", f=unchained_capital_export),
    MenuItem("Generic JSON", f=generic_skeleton),
    MenuItem("Export XPUB", menu=XpubExportMenu),
]

SDCardMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Verify Backup", f=verify_backup),
    MenuItem("Backup System", f=backup_everything),
    MenuItem("Dump Summary", f=dump_summary),
    MenuItem('Export Wallet', menu=WalletExportMenu),
    MenuItem('Sign Text File', predicate=has_secrets, f=sign_message_on_sd),
    MenuItem('Upgrade From SD', f=microsd_upgrade),
    MenuItem('Clone Coldcard', predicate=has_secrets, f=clone_write_data),
    MenuItem('List Files', f=list_files),
    MenuItem('NFC File Share', predicate=nfc_enabled, f=nfc_share_file),
    MenuItem('Format SD Card', f=wipe_sd_card),
    MenuItem('Format RAM Disk', predicate=vdisk_enabled, f=wipe_vdisk),
]

UpgradeMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Show Version', f=show_version),
    MenuItem('From MicroSD', f=microsd_upgrade),
    MenuItem('Bless Firmware', f=bless_flash),
]

if version.mk_num < 4:
    DevelopersMenu = [
        #         xxxxxxxxxxxxxxxx
        MenuItem("Normal USB Mode", f=dev_enable_protocol),
        MenuItem("Enable USB REPL", f=dev_enable_vcp),
        MenuItem("Enable USB Disk", f=dev_enable_disk),
        MenuItem("Wipe Patch Area", f=wipe_filesystem),         # needs better label
        MenuItem('Warm Reset', f=reset_self),
        MenuItem("Restore Txt Bkup", f=restore_everything_cleartext),
    ]
else:
    # Mk4 and later
    from mk4 import dev_enable_repl
    DevelopersMenu = [
        #         xxxxxxxxxxxxxxxx
        MenuItem("Serial REPL", f=dev_enable_repl),
        MenuItem("Wipe LFS", f=wipe_filesystem),                # kills settings, HSM stuff
        MenuItem('Warm Reset', f=reset_self),
        MenuItem("Restore Txt Bkup", f=restore_everything_cleartext),
    ]

AdvancedVirginMenu = [                  # No PIN, no secrets yet (factory fresh)
    #         xxxxxxxxxxxxxxxx
    MenuItem("View Identity", f=view_ident),
    MenuItem('Upgrade firmware', menu=UpgradeMenu),
    MenuItem('Paper Wallets', f=make_paper_wallet, predicate=lambda: make_paper_wallet),
    MenuItem('Perform Selftest', f=start_selftest),
    MenuItem('Secure Logout', f=logout_now),
]

AdvancedPinnedVirginMenu = [            # Has PIN but no secrets yet
    #         xxxxxxxxxxxxxxxx
    MenuItem("View Identity", f=view_ident),
    MenuItem("Upgrade", menu=UpgradeMenu),
    MenuItem('Paper Wallets', f=make_paper_wallet, predicate=lambda: make_paper_wallet),
    MenuItem('Perform Selftest', f=start_selftest),
    MenuItem("I Am Developer.", menu=maybe_dev_menu),
    MenuItem('Secure Logout', f=logout_now),
]

DebugFunctionsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Debug: assert', f=debug_assert),
    MenuItem('Debug: except', f=debug_except),
    MenuItem('Check: BL FW', f=check_firewall_read),
    MenuItem('Warm Reset', f=reset_self),
    #MenuItem("Perform Selftest", f=start_selftest),
]

SeedXORMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Split Existing", f=xor_split_start),
    MenuItem("Restore Seed XOR", f=xor_restore_start),
]

SeedFunctionsMenu = [
    MenuItem('View Seed Words', f=view_seed_words),     # text is a little wrong sometimes, rare
    MenuItem('Seed XOR', menu=SeedXORMenu),
    MenuItem("Destroy Seed", f=clear_seed),
    MenuItem('Lock Down Seed', f=convert_bip39_to_bip32),
]

DangerZoneMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Debug Functions", menu=DebugFunctionsMenu),       # actually harmless
    MenuItem("Seed Functions", menu=SeedFunctionsMenu),
    MenuItem("I Am Developer.", menu=maybe_dev_menu),
    MenuItem('Perform Selftest', f=start_selftest),             # little harmful
    MenuItem("Set High-Water", f=set_highwater),
    MenuItem('Wipe HSM Policy', f=wipe_hsm_policy, predicate=hsm_policy_available),
    MenuItem('Clear OV cache', f=wipe_ovc),
    ToggleMenuItem('Testnet Mode', 'chain', ['Bitcoin', 'Testnet3'], 
        value_map=['BTC', 'XTN'],
        story="Testnet must only be used by developers because \
correctly- crafted transactions signed on Testnet could be broadcast on Mainnet."),
    MenuItem('Settings space', f=show_settings_space),
]

BackupStuffMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Backup System", f=backup_everything),
    MenuItem("Verify Backup", f=verify_backup),
    MenuItem("Restore Backup", f=restore_everything),   # just a redirect really
    MenuItem('Clone Coldcard', predicate=has_secrets, f=clone_write_data),
    MenuItem("Dump Summary", f=dump_summary),
]

AdvancedNormalMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("View Identity", f=view_ident),
    MenuItem("Upgrade", menu=UpgradeMenu),
    MenuItem("Backup", menu=BackupStuffMenu),
    MenuItem("MicroSD Card", menu=SDCardMenu),
    MenuItem('Paper Wallets', f=make_paper_wallet, predicate=lambda: make_paper_wallet),
    MenuItem('User Management', menu=make_users_menu, predicate=lambda: version.has_fatram),
    MenuItem('Derive Entropy', f=drv_entro_start),
    MenuItem("Export XPUB", menu=XpubExportMenu),
    MenuItem("Danger Zone", menu=DangerZoneMenu),
]

# needs to create main wallet PIN
VirginSystem = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Choose PIN Code', f=initial_pin_setup),
    MenuItem('Advanced', menu=AdvancedVirginMenu),
    MenuItem('Bag Number', f=show_bag_number),
    MenuItem('Help', f=virgin_help),
]

ImportWallet = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("24 Words", menu=start_seed_import, arg=24),
    MenuItem("18 Words", menu=start_seed_import, arg=18),
    MenuItem("12 Words", menu=start_seed_import, arg=12),
    MenuItem("Restore Backup", f=restore_everything),
    MenuItem("Clone Coldcard", menu=clone_start),
    MenuItem("Import XPRV", f=import_xprv),
    MenuItem("Dice Rolls", f=import_from_dice),
    MenuItem("Seed XOR", f=xor_restore_start),
]

# has PIN, but no secret seed yet
EmptyWallet = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('New Wallet', f=pick_new_wallet),
    MenuItem('Import Existing', menu=ImportWallet),
    MenuItem('Help', f=virgin_help),
    MenuItem('Advanced', menu=AdvancedPinnedVirginMenu),
    MenuItem('Settings', menu=SettingsMenu),
]


# In operation, normal system, after a good PIN received.
NormalSystem = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Ready To Sign', f=ready2sign),
    MenuItem('Passphrase', f=start_b39_pw, predicate=lambda: settings.get('words', True)),
    MenuItem('Start HSM Mode', f=start_hsm_menu_item, predicate=hsm_policy_available),
    MenuItem("Address Explorer", f=address_explore),
    MenuItem('Secure Logout', f=logout_now),
    MenuItem('Advanced', menu=AdvancedNormalMenu),
    MenuItem('Settings', menu=SettingsMenu),
]


# Shown until unit is put into a numbered bag
FactoryMenu = [
    MenuItem('Bag Me Now'),     # nice to have NOP at top of menu
    MenuItem('DFU Upgrade', f=start_dfu),
    MenuItem('Show Version', f=show_version),
    MenuItem('Ship W/O Bag', f=ship_wo_bag),
    MenuItem("Debug Functions", menu=DebugFunctionsMenu),
    MenuItem("Perform Selftest", f=start_selftest),
]
