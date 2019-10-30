# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# flow.py - Menu structure
#
from menu import MenuItem
import version
from main import settings

from actions import *
from choosers import *
from multisig import make_multisig_menu
from address_explorer import address_explore

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
    MenuItem('Login Now', f=login_now, arg=1),
]

# Not reachable on Mark3 hardware
if not version.has_608:
    SecondaryPinChangesMenu = [
        #         xxxxxxxxxxxxxxxx
        MenuItem('Second Wallet', f=pin_changer, arg='secondary'),
        MenuItem('Duress PIN', f=pin_changer, arg='duress'),
        MenuItem('Login Now', f=login_now, arg=1),
    ]

async def which_pin_menu(_1,_2, item):
    if version.has_608: return PinChangesMenu
    from main import pa
    return PinChangesMenu if not pa.is_secondary else SecondaryPinChangesMenu

SettingsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Idle Timeout', chooser=idle_timeout_chooser),
    MenuItem('Touch Setting', chooser=sensitivity_chooser,
                                predicate=lambda: not version.has_membrane),
    MenuItem('Max Network Fee', chooser=max_fee_chooser),
    MenuItem('PIN Options', menu=which_pin_menu),
    MenuItem('Multisig Wallets', menu=make_multisig_menu),
    MenuItem('Blockchain', chooser=chain_chooser),
]

SDCardMenu = [
    MenuItem("Verify Backup", f=verify_backup),
    MenuItem("Backup System", f=backup_everything),
    MenuItem("Dump Summary", f=dump_summary),
    MenuItem('Upgrade From SD', f=microsd_upgrade),
    MenuItem("Electrum Wallet", f=electrum_skeleton),
    MenuItem("Wasabi Wallet", f=wasabi_skeleton),
    MenuItem('List Files', f=list_files),
    #MenuItem('Reformat Card', f=wipe_microsd),      # removed: not reliable enuf
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
    MenuItem('Perform Selftest', f=start_selftest),
    MenuItem('Secure Logout', f=logout_now),
]

AdvancedPinnedVirginMenu = [            # Has PIN but no secrets yet
    #         xxxxxxxxxxxxxxxx
    MenuItem("View Identity", f=view_ident),
    MenuItem("Upgrade", menu=UpgradeMenu),
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

DangerZoneMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Debug Functions", menu=DebugFunctionsMenu),       # actually harmless
    MenuItem('Lock Down Seed', f=convert_bip39_to_bip32,
                                predicate=lambda: settings.get('words', True)),
    MenuItem('View Seed Words', f=view_seed_words,
                                predicate=lambda: settings.get('words', True)),
    MenuItem("Destroy Seed", f=clear_seed),
    MenuItem("I Am Developer.", menu=maybe_dev_menu),
    MenuItem("Wipe Patch Area", f=wipe_filesystem),             # needs better label
    MenuItem('Perform Selftest', f=start_selftest),             # little harmful
    MenuItem("Set High-Water", f=set_highwater),
]

BackupStuffMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Backup System", f=backup_everything),
    MenuItem("Verify Backup", f=verify_backup),
    MenuItem("Restore Backup", f=restore_everything),   # just a redirect really
    MenuItem("Dump Summary", f=dump_summary),
]

AdvancedNormalMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("View Identity", f=view_ident),
    MenuItem("Upgrade", menu=UpgradeMenu),
    MenuItem("Backup", menu=BackupStuffMenu),
    MenuItem("MicroSD Card", menu=SDCardMenu),
    MenuItem("Address Explorer", f=address_explore),
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
    MenuItem("24 Words", menu=start_seed_import, arg=24),
    MenuItem("18 Words", menu=start_seed_import, arg=18),
    MenuItem("12 Words", menu=start_seed_import, arg=12),
    MenuItem("Restore Backup", f=restore_everything),
    MenuItem("Import XPRV", f=import_xprv),
    MenuItem("Dice Rolls", f=import_from_dice),
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
