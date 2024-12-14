# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# flow.py - Menu structure
#
from menu import MenuItem, PreloginToggleMenuItem, ToggleMenuItem, NonDefaultMenuItem, ShortcutItem
import version, charcodes
from glob import settings

from actions import *
from choosers import *
from mk4 import dev_enable_repl
from multisig import make_multisig_menu, import_multisig_nfc
from miniscript import make_miniscript_menu
from seed import make_ephemeral_seed_menu, make_seed_vault_menu, start_b39_pw
from address_explorer import address_explore
from drv_entro import drv_entro_start, password_entry
from backups import clone_start, clone_write_data
from xor_seed import xor_split_start, xor_restore_start
from countdowns import countdown_chooser
from paper import make_paper_wallet
from trick_pins import TrickPinMenu
from tapsigner import import_tapsigner_backup_file

# useful shortcut keys
from charcodes import KEY_QR, KEY_NFC


# Optional feature: HSM, depends on hardware
# - code for HSM support won't exist on some platforms, so don't call it
if version.supports_hsm:
    from hsm import hsm_policy_available
    from users import make_users_menu
else:
    hsm_policy_available = False
    make_users_menu = None

# Q related items
if version.has_battery:
    from battery import battery_idle_timeout_chooser, brightness_chooser
    from q1 import scan_and_bag
    from notes import make_notes_menu
else:
    battery_idle_timeout_chooser = None
    brightness_chooser = None
    scan_and_bag = None
    make_notes_menu = None


#
# NOTE: "Always In Title Case"
#
# - try to keep harmless things as first item: so double-tap of OK does no harm

#
# PREDICATES
# all predicates must be boolean value, or a callable to be evaluated at runtime
#

def has_se_secrets():
    # SE secret check, return False if only tmp secret is set
    from pincodes import pa
    return not pa.is_secret_blank()

def has_pin():
    from pincodes import pa
    return not pa.is_blank()

def has_secrets():
    # Secret is loaded, may be from SE or tmp
    from pincodes import pa
    return pa.has_secrets()

def nfc_enabled():
    from glob import NFC
    return bool(NFC)

def vdisk_enabled():
    return bool(settings.get('vidsk', 0))

def is_not_tmp():
    from pincodes import pa
    return not bool(pa.tmp_value)

def is_tmp():
    from pincodes import pa
    return bool(pa.tmp_value)

def has_real_secret():
    from pincodes import pa
    return (not pa.is_secret_blank()) and (not pa.tmp_value)

def word_based_seed():
    return settings.get("words", True)

def hsm_available():
    # contains hsm feature + can it be used (needs se2 secret and no tmp active)
    return version.supports_hsm and has_real_secret()

async def goto_home(*a):
    goto_top_menu()


HWTogglesMenu = [
    ToggleMenuItem('USB Port', 'du', ['Default On', 'Disable USB'], invert=True,
        on_change=change_usb_disable, story='''\
Blocks any data over USB port. Useful when your plan is air-gap usage.'''),
    ToggleMenuItem('Virtual Disk', 'vidsk', ['Default Off', 'Enable', 'Enable & Auto'],
        on_change=change_virtdisk_enable,
        story='''Coldcard can emulate a virtual disk drive (4MB) where new PSBT files \
can be saved. Signed PSBT files (transactions) will also be saved here. \n\
In "auto" mode, selects PSBT as soon as written.'''),
    ToggleMenuItem('NFC Sharing', 'nfc', ['Default Off', 'Enable NFC'], on_change=change_nfc_enable,
        story='''\
NFC (Near Field Communications) allows a phone to "tap" to send and receive data \
with the Coldcard.''',
        predicate=version.has_nfc),
]

# Mostly pre-login values here.
LoginPrefsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Change Main PIN', f=main_pin_changer),
    NonDefaultMenuItem('Trick PINs', 'tp', menu=TrickPinMenu.make_menu, predicate=has_real_secret),
    NonDefaultMenuItem('Set Nickname', 'nick', prelogin=True, f=pick_nickname),
    NonDefaultMenuItem('Scramble Keys', 'rngk', prelogin=True, f=pick_scramble, default_value=0),
    NonDefaultMenuItem('Kill Key', 'kbtn', prelogin=True, f=pick_killkey),
    NonDefaultMenuItem('Login Countdown', 'lgto', prelogin=True, chooser=countdown_chooser),
    NonDefaultMenuItem('MicroSD 2FA', 'sd2fa', menu=microsd_2fa, predicate=has_real_secret),
    PreloginToggleMenuItem('Calculator Login', 'calc', ['Default Off', 'Calculator Login'],
                           story=('Boots into calculator mode. Enter your PIN as formula to login, '
                                  'or 12- to see prefix words. Normal calculator math works too.'),
                           predicate=version.has_qwerty),
    MenuItem('Test Login Now', f=login_now, arg=1),
]

SettingsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Login Settings', menu=LoginPrefsMenu),
    MenuItem('Hardware On/Off', menu=HWTogglesMenu),
    NonDefaultMenuItem('Multisig Wallets', 'multisig',
                       menu=make_multisig_menu, predicate=has_secrets),
    NonDefaultMenuItem('Miniscript', 'miniscript',
                       menu=make_miniscript_menu, predicate=has_secrets),
    NonDefaultMenuItem('NFC Push Tx', 'ptxurl', menu=pushtx_setup_menu),
    MenuItem('Display Units', chooser=value_resolution_chooser),
    MenuItem('Max Network Fee', chooser=max_fee_chooser),
    MenuItem('Idle Timeout', chooser=idle_timeout_chooser),
    MenuItem('Idle Timeout (on battery)', chooser=battery_idle_timeout_chooser,
                                                 predicate=version.has_battery),
    MenuItem('LCD Brightness (on battery)', chooser=brightness_chooser,
                                                 predicate=version.has_battery),
    ToggleMenuItem('Delete PSBTs', 'del', ['Default Keep', 'Delete PSBTs'],
        story='''\
PSBT files (on SDCard) will be blanked & deleted after they are used. \
The signed transaction will be named <TXID>.txn, so the file name does not leak information.

MS-DOS tools should not be able to find the PSBT data (ie. undelete), but forensic tools \
which take apart the flash chips of the SDCard may still be able to find the \
data or filenames.'''),
    ToggleMenuItem('Menu Wrapping', 'wa', ['Default Off', 'Enable'],
           story='''When enabled, allows scrolling past menu top/bottom \
(wrap around). By default, this is only happens in very large menus.'''),
    ToggleMenuItem('Home Menu XFP', 'hmx', ['Only Tmp', 'Always Show'],
                   story=('Forces display of XFP (seed fingerprint) '
                          'at top of main menu. Normally, XFP is shown only when '
                          'temporary seed is active.\n\n'
                          'Master seed is displayed as <XFP>, temporary seeds as [XFP].'),
                   predicate=has_real_secret,
                   on_change=goto_home),
    ToggleMenuItem('Keyboard EMU', 'emu', ['Default Off', 'Enable'],
           on_change=usb_keyboard_emulation,
           predicate=has_secrets,  # cannot generate BIP85 passwords without secret
           story='''This mode adds a top-level menu item for typing \
deterministically-generated passwords (BIP-85), directly into an \
attached USB computer (as an emulated keyboard).'''),
]

XpubExportMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Segwit (BIP-84)", f=export_xpub, arg=84),
    MenuItem("Classic (BIP-44)", f=export_xpub, arg=44),
    MenuItem("Taproot/P2TR(86)", f=export_xpub, arg=86),
    MenuItem("P2WPKH/P2SH (49)", f=export_xpub, arg=49),
    MenuItem("Master XPUB", f=export_xpub, arg=0),
    MenuItem("Current XFP", f=export_xpub, arg=-1),
]

WalletExportMenu = [  
    #         xxxxxxxxxxxxxxxx
    MenuItem("Bitcoin Core", f=bitcoin_core_skeleton),
    MenuItem("Fully Noded", f=named_generic_skeleton, arg="Fully Noded"),
    MenuItem("Sparrow Wallet", f=named_generic_skeleton, arg="Sparrow"),
    MenuItem("Nunchuk", f=named_generic_skeleton, arg="Nunchuk"),
    MenuItem("Zeus", f=ss_descriptor_skeleton,
             arg=(True, [AF_P2WPKH, AF_P2WPKH_P2SH], "Zeus Wallet", "zeus-export.txt")),
    MenuItem("Electrum Wallet", f=electrum_skeleton),
    MenuItem("Theya", f=named_generic_skeleton, arg="Theya"),
    MenuItem("Wasabi Wallet", f=wasabi_skeleton),
    MenuItem("Unchained", f=unchained_capital_export),
    MenuItem("Lily Wallet", f=named_generic_skeleton, arg="Lily"),
    MenuItem("Samourai Postmix", f=samourai_post_mix_descriptor_export),
    MenuItem("Samourai Premix", f=samourai_pre_mix_descriptor_export),
    # MenuItem("Samourai BadBank", f=samourai_bad_bank_descriptor_export),  # not released yet
    MenuItem("Descriptor", f=ss_descriptor_skeleton),
    MenuItem("Generic JSON", f=generic_skeleton),
    MenuItem("Export XPUB", menu=XpubExportMenu),
    MenuItem("Dump Summary", predicate=has_secrets, f=dump_summary),
]

# useful even if no secrets, may operate on VDisk or SDCard when inserted
FileMgmtMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Verify Backup", f=verify_backup),
    MenuItem("Backup System", predicate=has_secrets, f=backup_everything),
    MenuItem('Export Wallet', predicate=has_secrets, menu=WalletExportMenu),        #dup elsewhere
    MenuItem('Sign Text File', predicate=has_secrets, f=sign_message_on_sd),
    MenuItem('Batch Sign PSBT', predicate=has_secrets, f=batch_sign),
    MenuItem('List Files', f=list_files),
    MenuItem('Verify Sig File', f=verify_sig_file),
    MenuItem('NFC File Share', predicate=nfc_enabled, f=nfc_share_file, shortcut=KEY_NFC),
    MenuItem('QR File Share', predicate=version.has_qr, f=qr_share_file, shortcut=KEY_QR),
    MenuItem('Clone Coldcard', predicate=has_secrets, f=clone_write_data),
    MenuItem('Format SD Card', f=wipe_sd_card),
    MenuItem('Format RAM Disk', predicate=vdisk_enabled, f=wipe_vdisk),
]

UpgradeMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Show Version', f=show_version),
    MenuItem('From MicroSD', f=microsd_upgrade, arg=False),
    MenuItem('From VirtDisk', predicate=vdisk_enabled, f=microsd_upgrade, arg=True),  # force_vdisk=True
]

DevelopersMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Serial REPL", f=dev_enable_repl),
    MenuItem('Warm Reset', f=reset_self),
    MenuItem("Restore Txt Bkup", f=restore_everything_cleartext),
]

AdvancedVirginMenu = [                  # No PIN, no secrets yet (factory fresh)
    #         xxxxxxxxxxxxxxxx
    MenuItem("View Identity", f=view_ident),
    MenuItem('Paper Wallets', f=make_paper_wallet),
    MenuItem('Perform Selftest', f=start_selftest),
    MenuItem('Secure Logout', f=logout_now, predicate=not version.has_battery),
]

AdvancedPinnedVirginMenu = [            # Has PIN but no secrets yet
    #         xxxxxxxxxxxxxxxx
    MenuItem("View Identity", f=view_ident),
    MenuItem("Temporary Seed", menu=make_ephemeral_seed_menu),
    MenuItem("Upgrade Firmware", menu=UpgradeMenu, predicate=is_not_tmp),
    MenuItem("File Management", menu=FileMgmtMenu),
    MenuItem('Paper Wallets', f=make_paper_wallet),
    MenuItem('Perform Selftest', f=start_selftest),
    MenuItem("I Am Developer.", menu=maybe_dev_menu),
    MenuItem('Secure Logout', f=logout_now, predicate=not version.has_battery),
]

DebugFunctionsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Keyboard Test", f=keyboard_test),
    MenuItem('BBQr Demo', f=debug_bbqr_test, predicate=version.has_qwerty),
    MenuItem('Debug: assert', f=debug_assert),
    MenuItem('Debug: except', f=debug_except),
    MenuItem('Check: BL FW', f=check_firewall_read),
    MenuItem('Warm Reset', f=reset_self),
    #MenuItem("Perform Selftest", f=start_selftest),
]

SeedXORMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Split Existing", f=xor_split_start, predicate=word_based_seed),
    MenuItem("Restore Seed XOR", f=xor_restore_start),
]

SeedFunctionsMenu = [
    MenuItem('View Seed Words', f=view_seed_words),     # text is a little wrong sometimes, rare
    MenuItem('Seed XOR', menu=SeedXORMenu),
    MenuItem("Destroy Seed", f=clear_seed, predicate=has_real_secret),
    MenuItem('Lock Down Seed', f=convert_ephemeral_to_master, predicate=is_tmp),
    MenuItem('Export SeedQR', f=export_seedqr, predicate=word_based_seed),
]

DangerZoneMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Debug Functions", menu=DebugFunctionsMenu),       # actually harmless
    MenuItem("Seed Functions", menu=SeedFunctionsMenu),
    MenuItem("I Am Developer.", menu=maybe_dev_menu),
    ToggleMenuItem('Seed Vault', 'seedvault', ['Default Off', 'Enable'],
                   on_change=change_seed_vault,
                   story=("Enable Seed Vault? Adds prompt to store temporary seeds "
                          "into Seed Vault, where they can easily be reused later.\n\n"
                          "WARNING: Seed Vault is encrypted (AES-256-CTR) by your seed,"
                          " but not held directly inside secure elements. Backups are required"
                          " after any change to vault! Recommended for experiments or temporary use."),
                   predicate=has_se_secrets),
    MenuItem('Perform Selftest', f=start_selftest),             # little harmful
    MenuItem("Set High-Water", f=set_highwater),
    MenuItem('Wipe HSM Policy', f=wipe_hsm_policy, predicate=hsm_policy_available),
    MenuItem('Clear OV cache', f=wipe_ovc),
    MenuItem("Clear Address cache" if version.has_qwerty else "Clear Addr cache", f=wipe_address_cache),
    ToggleMenuItem("Sighash Checks", "sighshchk", ["Default: Block", "Warn"],
                   invert=True,
                   story='''\
If you disable sighash flag restrictions, and ignore the \
warnings, funds can be stolen by specially crafted PSBT or MitM.

Keep blocked unless you intend to sign special transactions.'''),
    ToggleMenuItem('Testnet Mode', 'chain', ['Bitcoin', 'Testnet3', 'Regtest'],
        value_map=['BTC', 'XTN', 'XRT'],
        on_change=change_which_chain,
        story="Testnet must only be used by developers because \
correctly- crafted transactions signed on Testnet could be broadcast on Mainnet."),
    ToggleMenuItem('AE Start Index', 'aei', ['Default Off', 'Enable'], story=(
              "Enable this option to add new menu item to Address Explorer "
              "allowing override of start index. By default start index is zero.\n\n"
              "WARNING: Some wallets will not recognize addresses that are past their gap limit"
              " and your deposits will seem to disappear."),
                   predicate=has_secrets),
    ToggleMenuItem('B85 Idx Values', 'b85max', ['Default Off', 'Unlimited'],
                   story=("Allow unlimited indexes for BIP-85 derivations?\n\n"
                          "DANGER: If you forget this index number, getting your funds "
                          "back will be a difficult search problem."),
                   predicate=has_secrets),
    MenuItem('Settings Space', f=show_settings_space),
    MenuItem('MCU Key Slots', f=show_mcu_keys_left),
    MenuItem('Bless Firmware', f=bless_flash),          # no need for this anymore?
    MenuItem('Reflash GPU', f=reflash_gpu, predicate=version.has_qwerty),
    MenuItem("Wipe LFS", f=wipe_filesystem),    # kills other-seed settings, HSM stuff, addr cache
]

BackupStuffMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Backup System", f=backup_everything),
    MenuItem("Verify Backup", f=verify_backup),
    MenuItem("Restore Backup", f=restore_everything),   # just a redirect really
    MenuItem('Clone Coldcard', predicate=has_secrets, f=clone_write_data),
]

NFCToolsMenu = [
    MenuItem('Sign PSBT', f=nfc_sign_psbt),
    MenuItem('Show Address', f=nfc_show_address),
    MenuItem('Sign Message', f=nfc_sign_msg),
    MenuItem('Verify Sig File', f=nfc_sign_verify),
    MenuItem('Verify Address', f=nfc_address_verify),
    MenuItem('File Share', f=nfc_share_file),
    MenuItem('Import Multisig', f=import_multisig_nfc),
    MenuItem('Push Transaction', f=nfc_pushtx_file, predicate=lambda: settings.get("ptxurl", False)),
]

AdvancedNormalMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Backup", menu=BackupStuffMenu),
    MenuItem('Export Wallet', predicate=has_secrets, menu=WalletExportMenu, shortcut='x'),  # also inside FileMgmt
    MenuItem("Upgrade Firmware", menu=UpgradeMenu, predicate=is_not_tmp),
    MenuItem("File Management", menu=FileMgmtMenu),
    NonDefaultMenuItem('Secure Notes & Passwords', 'notes', menu=make_notes_menu,
                            predicate=version.has_qwerty),
    MenuItem('Derive Seed B85' if not version.has_qwerty else 'Derive Seeds (BIP-85)',
                            f=drv_entro_start),
    MenuItem("View Identity", f=view_ident),
    MenuItem("Temporary Seed", menu=make_ephemeral_seed_menu),
    MenuItem('Paper Wallets', f=make_paper_wallet),
    ToggleMenuItem('Enable HSM', 'hsmcmd', ['Default Off', 'Enable'],
                   story=("Enable HSM? Enables all user management commands, and other HSM-only USB commands. "
                          "By default these commands are disabled."),
                   predicate=hsm_available),
    MenuItem('User Management', menu=make_users_menu,
             predicate=hsm_available),
    MenuItem('NFC Tools', predicate=nfc_enabled, menu=NFCToolsMenu, shortcut=KEY_NFC),
    MenuItem("Danger Zone", menu=DangerZoneMenu, shortcut='z'),
]

# needs to create main wallet PIN
VirginSystem = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Choose PIN Code', f=initial_pin_setup),
    MenuItem('Advanced/Tools', menu=AdvancedVirginMenu),
    MenuItem('Bag Number', f=show_bag_number),
    MenuItem('Help', f=virgin_help, predicate=not version.has_qwerty),
]

ImportWallet = [
    MenuItem("12 Words", menu=start_seed_import, arg=12),
    MenuItem("18 Words", menu=start_seed_import, arg=18),
    MenuItem("24 Words", menu=start_seed_import, arg=24),
    MenuItem('Scan QR Code', predicate=version.has_qr,
             shortcut=KEY_QR, f=scan_any_qr, arg=(True, False)),
    MenuItem("Restore Backup", f=restore_everything),
    MenuItem("Clone Coldcard", menu=clone_start),
    MenuItem("Import XPRV", f=import_xprv, arg=False),  # ephemeral=False
    MenuItem("Tapsigner Backup", f=import_tapsigner_backup_file, arg=False),
    MenuItem("Seed XOR", f=xor_restore_start),
]

SeedFromDiceMenu = [
    MenuItem("12 Word Dice Roll", f=new_from_dice, arg=12),
    MenuItem("24 Word Dice Roll", f=new_from_dice, arg=24),
]

NewSeedMenu = [
    MenuItem("12 Words", f=pick_new_seed, arg=12),
    MenuItem("24 Words", f=pick_new_seed, arg=24),
    MenuItem("Advanced", menu=SeedFromDiceMenu),
]

# has PIN, but no secret seed yet
EmptyWallet = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('New Seed Words', menu=NewSeedMenu),
    MenuItem('Import Existing', menu=ImportWallet),
    MenuItem("Migrate Coldcard", menu=clone_start),
    MenuItem('Help', f=virgin_help, predicate=not version.has_qwerty),
    MenuItem('Advanced/Tools', menu=AdvancedPinnedVirginMenu),
    MenuItem('Settings', menu=SettingsMenu),
]

# In operation, normal system, after a good PIN received.
# - key shortcuts in place for all items that will be shown on Q
NormalSystem = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Ready To Sign', f=ready2sign, shortcut='r'),
    MenuItem('Passphrase', menu=start_b39_pw, predicate=word_based_seed, shortcut='p'),
    MenuItem('Scan Any QR Code', predicate=version.has_qr,
         shortcut=KEY_QR, f=scan_any_qr, arg=(False, True)),
    MenuItem('Start HSM Mode', f=start_hsm_menu_item, predicate=hsm_policy_available),
    MenuItem("Address Explorer", menu=address_explore, shortcut='x'),
    MenuItem('Secure Notes & Passwords', menu=make_notes_menu, shortcut='n',
                 predicate=lambda: version.has_qwerty and (settings.get("notes", False) != False)),
    MenuItem('Type Passwords', f=password_entry, shortcut='t',
             predicate=lambda: settings.get("emu", False) and has_secrets()),
    MenuItem('Seed Vault', menu=make_seed_vault_menu, shortcut='v',
             predicate=lambda: settings.master_get('seedvault') and has_secrets()),
    MenuItem('Advanced/Tools', menu=AdvancedNormalMenu, shortcut='t'),
    MenuItem('Settings', menu=SettingsMenu, shortcut='s'),
    MenuItem('Secure Logout', f=logout_now, predicate=not version.has_battery),
    ShortcutItem(KEY_NFC, predicate=nfc_enabled, menu=NFCToolsMenu),
]

# Shown until unit is put into a numbered bag
FactoryMenu = [
    MenuItem('Version: ' + version.get_mpy_version()[1], f=show_version),
    MenuItem('Bag Me Now', f=scan_and_bag),
    MenuItem('DFU Upgrade', f=start_dfu, shortcut='u'),
    MenuItem('Ship W/O Bag', f=ship_wo_bag),
    MenuItem("Debug Functions", menu=DebugFunctionsMenu, shortcut='f'),
    MenuItem("Perform Selftest", f=start_selftest, shortcut='s'),
]
