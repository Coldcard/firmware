# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# flow.py - Menu structure
#
from menu import MenuItem
import version
from nvstore import settings

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
    if version.has_608: return PinChangesMenu
    from pincodes import pa
    return PinChangesMenu if not pa.is_secondary else SecondaryPinChangesMenu

def has_secrets():
    from pincodes import pa
    return not pa.is_secret_blank()

SettingsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Idle Timeout', chooser=idle_timeout_chooser),
    MenuItem('Login Countdown', chooser=countdown_chooser),
    MenuItem('Max Network Fee', chooser=max_fee_chooser),
    MenuItem('PIN Options', menu=which_pin_menu),
    MenuItem('Multisig Wallets', menu=make_multisig_menu),
    MenuItem('Set Nickname', f=pick_nickname),
    MenuItem('Scramble Keypad', f=pick_scramble),
    MenuItem('Delete PSBTs', f=pick_inputs_delete),
    MenuItem('Disable USB', chooser=disable_usb_chooser),
    MenuItem('Display Units', chooser=value_resolution_chooser),
]

WalletExportMenu = [  
    #         xxxxxxxxxxxxxxxx (alphabetical ordering)
    MenuItem("Bitcoin Core", f=bitcoin_core_skeleton),
    MenuItem("Electrum Wallet", f=electrum_skeleton),
    MenuItem("Wasabi Wallet", f=wasabi_skeleton),
    MenuItem("Unchained Capital", f=unchained_capital_export),
    MenuItem("Generic JSON", f=generic_skeleton),
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
    MenuItem('Format Card', f=wipe_sd_card),
]

UpgradeMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Show Version', f=show_version),
    MenuItem('From MicroSD', f=microsd_upgrade),
    MenuItem('Bless Firmware', f=bless_flash),
]

DevelopersMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Normal USB Mode", f=dev_enable_protocol),
    MenuItem("Enable USB REPL", f=dev_enable_vcp),
    MenuItem("Enable USB Disk", f=dev_enable_disk),
    MenuItem("Wipe Patch Area", f=wipe_filesystem),
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
    MenuItem("Wipe Patch Area", f=wipe_filesystem),             # needs better label
    MenuItem('Perform Selftest', f=start_selftest),             # little harmful
    MenuItem("Set High-Water", f=set_highwater),
    MenuItem('Wipe HSM Policy', f=wipe_hsm_policy, predicate=hsm_policy_available),
    MenuItem('Clear OV cache', f=wipe_ovc),
    MenuItem('Testnet Mode', f=confirm_testnet_mode),
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
