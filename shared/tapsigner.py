# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# tapsigner.py - TAPSIGNER backup file support
#
import gc, sys, ustruct, ngu, chains, ure, time
from ubinascii import unhexlify as a2b_hex
from ux import ux_show_story, the_ux, ux_confirm, ux_dramatic_pause, ux_aborted
from ux import ux_enter_bip32_index, ux_input_text, import_export_prompt
from export import make_json_wallet, make_summary_file, make_descriptor_wallet_export
from export import make_bitcoin_core_wallet, generate_wasabi_wallet, generate_generic_export
from export import generate_unchained_export, generate_electrum_wallet
from files import CardSlot, CardMissingError, needs_microsd
from glob import settings
from charcodes import KEY_NFC, KEY_QR, KEY_CANCEL
from actions import file_picker, import_extended_key_as_secret

def decrypt_tapsigner_backup(backup_key, data):
    try:
        backup_key = a2b_hex(backup_key)
        decrypt = ngu.aes.CTR(backup_key, bytes(16))  # IV 0
        decrypted = decrypt.cipher(data).decode().strip()
        # format of TAPSIGNER backup is known in advance
        # extended private key is expected at the beginning of the first line
        assert decrypted[1:4] == "prv"
    except Exception:
        raise ValueError("Decryption failed - wrong key?")

    return decrypted.split("\n")

async def import_tapsigner_backup_file(_1, _2, item):
    from glob import NFC

    ephemeral = item.arg
    if not ephemeral:
        from pincodes import pa
        assert pa.is_secret_blank()  # "must not have secret"

    meta = "from "
    label = "TAPSIGNER encrypted backup file"
    choice = await import_export_prompt(label, is_import=True)

    if choice == KEY_CANCEL:
        return
    elif choice == KEY_NFC:
        data = await NFC.read_tapsigner_b64_backup()
        if not data:
            # failed to get any data - exit
            # error already displayed in nfc.py
            return
    elif choice == KEY_QR:
        # how is binary encoded? who made this QR??!
        from ux_q1 import QRScannerInteraction
        from ubinascii import a2b_base64
        from ubinascii import unhexlify as a2b_hex

        prob = None
        while 1:
            data = await QRScannerInteraction.scan(
                            'Scan TAPSIGNER backup data', prob)
            if not data: return     # pressed cancel

            # guess at serialization between Base64 and Hex
            try:
                # pure hex, the smarter encoding (when in caps)
                data = a2b_hex(data)
            except ValueError:
                try:
                    data = a2b_base64(data)
                except ValueError:
                    prob = 'Expected HEX digits or Base64 encoded binary'
                    continue
            break
    else:
        fn = await file_picker(suffix="aes", min_size=100, max_size=160, **choice)
        if not fn: return
        meta += (" (%s)" % fn)
        with CardSlot(**choice) as card:
            with open(fn, 'rb') as fp:
                data = fp.read()

    if await ux_show_story("Make sure to have your TAPSIGNER handy as you will need to provide "
                           "'Backup Password' from the back of the card in the next step.\n\n"
                           "Press OK to continue X to cancel.") != "y":
        return

    while True:
        backup_key = await ux_input_text("", confirm_exit=False, hex_only=True,
                            min_len=32, max_len=32, prompt='Backup Password (32 hex digits)')
        if backup_key is None:
            return

        assert len(backup_key) == 32

        try:
            extended_key, derivation = decrypt_tapsigner_backup(backup_key, data)
            break
        except ValueError as e:
            await ux_show_story(title="FAILURE", msg=str(e))
            continue

    await import_extended_key_as_secret(extended_key, ephemeral, meta=meta)

# EOF
