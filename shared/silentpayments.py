# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# silentpayments.py - BIP-352/BIP-375 Silent Payment Logic
#
# Consolidates cryptographic primitives and PSBT handling logic for Silent Payments.
#

import ckcc
import ngu
from dleq import generate_dleq_proof, verify_dleq_proof
from exceptions import FatalPSBTIssue
from precomp_tag_hash import BIP352_SHARED_SECRET_TAG_H, BIP352_INPUTS_TAG_H, BIP352_LABEL_TAG_H, TAP_TWEAK_H
from serializations import SIGHASH_ALL, SIGHASH_DEFAULT
from ubinascii import unhexlify as a2b_hex
from utils import keypath_to_str

# BIP-341 NUMS point (Nothing Up My Sleeve) - x-only (32 bytes)
NUMS_H = a2b_hex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
SECP256K1_ORDER = ngu.secp256k1.curve_order_int()

# -----------------------------------------------------------------------------
# Silent Payments Cryptographic Primitives
# -----------------------------------------------------------------------------

def _compute_ecdh_share(a_sum, B_scan_bytes):
    """
    Compute BIP-375 ECDH share for silent payments 

    Formula: ecdh_share = a_sum * B_scan

    Args:
        a_sum: Combined private key as scalar
        B_scan_bytes: Scan public key (33 bytes compressed)

    Returns:
        bytes: ECDH share as compressed public key (33 bytes)
    """
    privkey_bytes = a_sum.to_bytes(32, "big")
    try:
        ngu.secp256k1.pubkey(B_scan_bytes)
    except Exception as e:
        raise ValueError("Invalid scan public key") from e
    
    return ngu.secp256k1.ec_pubkey_tweak_mul(B_scan_bytes, privkey_bytes)

def _compute_shared_secret_tweak(shared_secret_bytes, k):
    """
    Compute BIP-352 shared secret tweak for output index k

    BIP-352 formula: t_k = hash_BIP0352/SharedSecret(shared_secret || ser_32(k))

    Args:
        shared_secret_bytes: Combined shared secret (33 bytes compressed point)
        k: Output index (0-based)

    Returns:
        bytes: Shared secret tweak as 32-byte scalar (reduced mod curve order)
    """
    # Concatenate shared_secret || k
    msg = shared_secret_bytes + k.to_bytes(4, "big")
    tweak_bytes = ngu.hash.sha256t(BIP352_SHARED_SECRET_TAG_H, msg, True)

    # Convert hash to scalar (reduce by curve order)
    return (int.from_bytes(tweak_bytes, "big") % SECP256K1_ORDER).to_bytes(32, "big")

def _compute_input_hash(outpoints, A_sum_bytes):
    """
    Compute BIP-352 input hash

    BIP-352 formula: input_hash = hash_BIP0352/Inputs(smallest_outpoint || A_sum)

    Args:
        outpoints: List of (txid, vout) tuples, where txid is 32 bytes and vout as (4 bytes little-endian)
        A_sum_bytes: Sum of all eligible input public keys (33 bytes compressed)

    Returns:
        bytes: Input hash as 32-byte scalar (reduced mod curve order)
    """
    # BIP-352: use only the lexicographically smallest outpoint
    smallest = min(outpoints, key=lambda x: (x[0], x[1]))
    msg = smallest[0] + smallest[1] + A_sum_bytes

    input_hash_bytes = ngu.hash.sha256t(BIP352_INPUTS_TAG_H, msg, True)

    return (int.from_bytes(input_hash_bytes, "big") % SECP256K1_ORDER).to_bytes(32, "big")

def _combine_pubkeys(pubkeys):
    """
    Combine a list of public keys into a single public key

    Args:
        pubkeys: List of public keys (33 bytes compressed)

    Returns:
        bytes: Combined public key (33 bytes compressed)

    Raises:
        ValueError: If list is empty or keys are invalid
    """
    if not pubkeys:
        raise ValueError("No public keys to combine")

    combined_pk = pubkeys[0]
    try:
        for pk in pubkeys[1:]:
            combined_pk = ngu.secp256k1.ec_pubkey_combine(combined_pk, pk)
    except Exception as e:
        raise ValueError("Failed to combine public keys") from e

    return combined_pk

def _compute_silent_payment_output_script(
    outpoints, A_sum_bytes, ecdh_share_bytes, B_spend, k=0
):
    """
    Compute the P2TR scriptPubKey for silent payment with output index k.

    BIP-352 formula: P_k = B_spend + t_k * G
    where input_hash = hash_BIP0352/Inputs(outpoints || A_sum)
          t_k = hash_BIP0352/SharedSecret(ecdh_share * input_hash || ser_32(k))

    Args:
        outpoints: List of (txid, vout) tuples from eligible inputs
        A_sum_bytes: Sum of eligible input public keys (33 bytes compressed)
        ecdh_share_bytes: ECDH share point (33 bytes compressed)
        B_spend: Recipient spend public key (33 bytes compressed)
        k: Output index for this recipient

    Returns:
        bytes: P2TR scriptPubKey (34 bytes: OP_1 <32-byte x-only pubkey>)

    Raises:
        ValueError: If B_spend or output_pubkey is invalid
    """
    try:
        ngu.secp256k1.pubkey(B_spend)
    except Exception:
        raise ValueError("Invalid spend public key")

    # Compute shared secret using input hash and ecdh_share
    input_hash_bytes = _compute_input_hash(outpoints, A_sum_bytes)
    shared_secret_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(ecdh_share_bytes, input_hash_bytes)

    # Compute shared secret tweak
    tweak_bytes = _compute_shared_secret_tweak(shared_secret_bytes, k)

    # Compute t_k * G using the generator point
    G = ngu.secp256k1.generator()
    tweak_point = ngu.secp256k1.ec_pubkey_tweak_mul(G, tweak_bytes)

    # Derive output pubkey: P_k = B_spend + t_k * G
    output_pubkey = ngu.secp256k1.ec_pubkey_combine(B_spend, tweak_point)

    if len(output_pubkey) != 33:
        raise ValueError("Invalid pubkey length")
    x_only = output_pubkey[1:]

    return b"\x51\x20" + x_only

def _compute_silent_payment_spending_privkey(b_spend_bytes, sp_tweak_bytes):
    """
    Compute private key for spending a silent payment output
    
    BIP-352 formula for spending: d_k = (b_spend + t_k) mod n
    where:
    - b_spend is the base spend private key
    - t_k is the combined tweak (shared secret + label if applicable) from PSBT_IN_SP_TWEAK
    - n is the secp256k1 curve order
    
    Args:
        b_spend_bytes: Base spend private key
        sp_tweak_bytes: 32-byte scalar tweak from PSBT_IN_SP_TWEAK
    
    Returns:
        int: Tweaked spending private key
    
    Raises:
        ValueError: If sp_tweak or spending_privkey is invalid
    """
    if len(sp_tweak_bytes) != 32:
        raise ValueError("SP tweak must be 32 bytes")

    sp_tweak_int = int.from_bytes(sp_tweak_bytes, 'big')
    b_spend_int = int.from_bytes(b_spend_bytes, 'big')

    if b_spend_int == 0 or b_spend_int >= SECP256K1_ORDER:
        raise ValueError("Spend private key is out of valid range")
    if sp_tweak_int >= SECP256K1_ORDER:
        raise ValueError("SP tweak is out of valid range")

    # Compute tweaked key: d_k = (d_spend + t_k) mod n
    spending_sk = (b_spend_int + sp_tweak_int) % SECP256K1_ORDER

    if spending_sk == 0:
        raise ValueError("Resulting spending key is zero (invalid)")
    
    return spending_sk

def _apply_label_to_spend_key(B_spend, b_scan, label):
    """
    Apply BIP-352 label tweak to spend key

    BIP-352 formula: B_m = B_spend + hash_BIP0352/Label(b_scan || m)*G
    
    Args:
        B_spend: Base spend public key (33 bytes compressed)
        b_scan: Scan private key (32 bytes)
        label: Label integer (0 for change, >0 for other purposes)
    
    Returns:
        bytes: B_spend_labeled public key (33 bytes compressed)
    """
    msg = b_scan + label.to_bytes(4, 'big')
    tweak_bytes = ngu.hash.sha256t(BIP352_LABEL_TAG_H, msg, True)
    tweak_scalar = int.from_bytes(tweak_bytes, 'big') % SECP256K1_ORDER

    # Compute tweaked pubkey
    G = ngu.secp256k1.generator()
    Tweak_pubkey = ngu.secp256k1.ec_pubkey_tweak_mul(G, tweak_scalar.to_bytes(32, 'big'))
    
    # Apply tweak: B_m = B_spend + Tweak
    return ngu.secp256k1.ec_pubkey_combine(B_spend, Tweak_pubkey)


# -----------------------------------------------------------------------------
# Input Eligibility (BIP-352)
# -----------------------------------------------------------------------------

def _is_p2pkh(spk):
    # OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return (
        len(spk) == 25
        and spk[0] == 0x76
        and spk[1] == 0xA9
        and spk[2] == 0x14
        and spk[-2] == 0x88
        and spk[-1] == 0xAC
    )

def _is_p2wpkh(spk):
    # OP_0 OP_PUSHBYTES_20 <20 bytes>
    return len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14

def _is_p2tr(spk):
    # OP_1 OP_PUSHBYTES_32 <32 bytes>
    return len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20

def _is_p2sh(spk):
    # OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
    return len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[-1] == 0x87


# -----------------------------------------------------------------------------
# PSBT Mixin
# -----------------------------------------------------------------------------

class SilentPaymentsMixin:
    """
    Mixin class for psbtObject to handle Silent Payments logic.

    This class assumes it is mixed into psbtObject and has access to:
    - self.inputs
    - self.outputs
    - self.get()
    - self.my_xfp
    - self.parse_xfp_path()
    """

    def encode_silent_payment_address(self, output):
        """
        Encode a human-readable Silent Payment address

        Uses current chain's HRP for encoding

        Args:
            output: Output object from self.outputs

        Returns:
            str: bech32m-encoded Silent Payment address (e.g., "sp1...")
        """
        if not output.sp_v0_info:
            raise ValueError("Output is not a silent payment output")

        scan_key = output.sp_v0_info[:33]
        spend_key = output.sp_v0_info[33:]

        # Get Silent Payment HRP from current chain
        import chains

        hrp = chains.current_chain().sp_hrp
        version = 0  # Currently only v0 supported
        return ngu.codecs.bip352_encode(hrp, scan_key, spend_key, version)

    def preview_silent_payment_outputs(self):
        """
        Computes ECDH shares and output scripts for silent payment outputs if we have the necessary information.

        Notes:
        - This function is intended to be called during the preview phase, before signing.
        - Single signer should be able to generate output and preview immediately.
        - Multi-signer should generate shares and prompt user to collect all shares if not complete.

        Returns:
            bool: True if output scripts were computed and are ready for preview
                  False if we generated shares but are waiting on others, or if we don't have necessary info to proceed
        """
        try:
            import stash

            with stash.SensitiveValues() as sv:
                result = self._process_silent_payments(sv) # TODO: should False raise an exception instead?
                self.sp_processed = result
                return result

        except FatalPSBTIssue:
            raise
        except Exception as e:
            print("SP preview failed: %s" % e)
            return False

    def process_silent_payments_for_signing(self, sv, dis):
        """
        Reference notes for preview_silent_payment_outputs

        Notes:
        - This function should skip share generation but checks for completeness before attempting to sign.

        Returns:
            bool: True if coverage is complete
                  False if we generated shares but are waiting on others, or if we don't have necessary info to proceed
        """
        dis.fullscreen("Silent Payment...")

        if not self.sp_processed:
            self._process_silent_payments(sv)

        if self._is_ecdh_coverage_complete():
            dis.fullscreen("Computing Outputs...")
            self._compute_silent_payment_output_scripts()
            return True

        return False

    def render_silent_payment_output_string(self, output):
        """
        Render a human-readable Silent Payment output string for displaying on screen

        Args:
            output: Output object from self.outputs

        Returns:
            str: Human-readable Silent Payment output string
        """
        if not output.sp_v0_info:
            raise ValueError("Output is not a silent payment output")

        return " - silent payment address -\n%s\n" % self.encode_silent_payment_address(output)


    # -----------------------------------------------------------------------------
    # Input Helper Functions
    # -----------------------------------------------------------------------------

    def _is_input_eligible(self, inp):
        # Check if input is eligible for silent payments per BIP-352
        # Returns (bool)
        spk = inp.utxo_spk
        if not spk:
            return False

        if not (_is_p2pkh(spk) or _is_p2wpkh(spk) or _is_p2tr(spk) or _is_p2sh(spk)):
            return False

        if _is_p2tr(spk):
            if inp.taproot_internal_key:
                tap_ik = self.get(inp.taproot_internal_key)
                if tap_ik == NUMS_H:
                    return False

        if _is_p2sh(spk):
            if inp.redeem_script:
                rs = self.get(inp.redeem_script)
                if not _is_p2wpkh(rs):
                    return False
            else:
                return False

        return True

    def _pubkey_from_input(self, inp):
        """
        Extract the BIP-352 contributing public key from an input

        Note:
            Spending SP: use PSBT_IN_SPEND_BIP32_DERIVATION
            P2TR: use PSBT_IN_WITNESS_UTXO to fetch (x-only -> compressed with 0x02)
            non-taproot: use BIP32 derivation pubkey (first 33-byte key)

        Returns 33-byte compressed pubkey or None.
        """
        if not self._is_input_eligible(inp):
            return None

        spk = inp.utxo_spk
        if inp.sp_spend_bip32_derivation:
            _, val_coords = inp.sp_spend_bip32_derivation
            xfp_path = self.parse_xfp_path(val_coords)
            if xfp_path[0] == self.my_xfp:
                pk = self.get(val_coords)
                if len(pk) == 33:
                    return pk

        if spk and _is_p2tr(spk):
            return b"\x02" + spk[2:34]
        else:
            if inp.subpaths:
                for pk_coords, _ in inp.subpaths:
                    pk = self.get(pk_coords)
                    if len(pk) == 33:
                        return pk

        return None

    def _tweak_p2tr_privkey(self, privkey_int, inp):
        """
        Tweak a P2TR private key according to BIP-352

        Args:
            privkey_int (int): The internal private key as an integer
            inp: The input object containing Taproot information

        Note:
            keypair.xonly_tweak_add().privkey() returns the tweaked key without normalizing the output to even Y

        Returns:
            int: The tweaked private key as an integer
        """
        G = ngu.secp256k1.generator()
        # normalize internal key to even Y, extract x-only.
        internal_pub = ngu.secp256k1.ec_pubkey_tweak_mul(G, privkey_int.to_bytes(32, 'big'))
        if internal_pub[0] == 0x03:
            privkey_int = SECP256K1_ORDER - privkey_int
        internal_xonly = internal_pub[1:]
        # compute TapTweak hash (with merkle root if script tree present).
        tweak_data = internal_xonly
        if inp.taproot_merkle_root:
            tweak_data = internal_xonly + self.get(inp.taproot_merkle_root)
        t = ngu.hash.sha256t(TAP_TWEAK_H, tweak_data, True)
        # add tweak scalar to get output private key.
        d = (privkey_int + int.from_bytes(t, 'big')) % SECP256K1_ORDER
        # negate if tweaked pubkey has odd Y (so d*G matches 0x02||x(Q)).
        output_pub = ngu.secp256k1.ec_pubkey_tweak_mul(G, d.to_bytes(32, 'big'))
        if output_pub[0] == 0x03:
            d = SECP256K1_ORDER - d
        return d

    # -----------------------------------------------------------------------------
    # Validation Functions
    # -----------------------------------------------------------------------------

    def _process_silent_payments(self, sv):
        """
        Core SP workflow: validate, compute shares, compute scripts if ready.

        Returns True if output scripts were computed (ready to sign).
        """
        if not self.has_silent_payment_outputs():
            return False
        self._validate_psbt_structure()
        self._validate_input_eligibility()
        self._validate_ecdh_coverage()

        if not self._compute_and_store_ecdh_shares(sv):
            return False

        if self._is_ecdh_coverage_complete():
            self._compute_silent_payment_output_scripts()
            self._detect_sp_change_outputs(sv)
            return True

        return False

    def _detect_sp_change_outputs(self, sv):
        """
        Mark SP outputs as change if sp_v0_label is present and keys match our wallet.

        Note:
            Must be called while SensitiveValues context is open.
 
        No return value; modifies self.outputs 'is_change' in place.
        """
        import chains
        coin_type = chains.current_chain().b44_cointype

        scan_node = sv.derive_path("m/352h/%dh/0h/1h/0" % coin_type, register=False)
        spend_node = sv.derive_path("m/352h/%dh/0h/0h/0" % coin_type, register=False)

        b_scan_bytes = scan_node.privkey()
        B_scan_bytes = scan_node.pubkey()
        B_spend_bytes = spend_node.pubkey()

        B_spend_labeled = _apply_label_to_spend_key(B_spend_bytes, b_scan_bytes, 0)

        for outp in self.outputs:
            if not outp.sp_v0_info or not outp.sp_v0_label:
                continue
            label_val = int.from_bytes(outp.sp_v0_label, 'little')
            if label_val != 0:
                continue
            if outp.sp_v0_info[:33] != B_scan_bytes:
                continue
            if outp.sp_v0_info[33:66] != B_spend_labeled:
                continue
            outp.is_change = True

    def _validate_psbt_structure(self):
        """
        Validate PSBT structure requirements for silent payments

        Raises FatalPSBTIssue if any structural requirements are violated
        """
        for i, outp in enumerate(self.outputs):
            has_sp_info = bool(outp.sp_v0_info)
            has_sp_label = bool(outp.sp_v0_label)
            has_script = bool(outp.script and self.get(outp.script))
            
            # Output must have script or SP info
            if not has_script and not has_sp_info:
                raise FatalPSBTIssue(
                    "Output #%d must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO" % i
                )

            if has_sp_label and not has_sp_info:
                raise FatalPSBTIssue(
                    "Output #%d has SP label but missing SP_V0_INFO" % i
                )

            if has_sp_info:
                if len(outp.sp_v0_info) != 66:
                    raise FatalPSBTIssue(
                        "Output #%d SP_V0_INFO wrong size (%d bytes, expected 66)"
                        % (i, len(outp.sp_v0_info))
                    )

        # Validate ECDH share sizes (33 bytes) and DLEQ proof sizes (64 bytes)
        if self.sp_global_ecdh_shares:
            for _, share in self.sp_global_ecdh_shares.items():
                if len(share) != 33:
                    raise FatalPSBTIssue(
                        "Global ECDH share wrong size (%d bytes, expected 33)"
                        % len(share)
                    )

        if self.sp_global_dleq_proofs:
            for _, proof in self.sp_global_dleq_proofs.items():
                if len(proof) != 64:
                    raise FatalPSBTIssue(
                        "Global DLEQ proof wrong size (%d bytes, expected 64)"
                        % len(proof)
                    )

        for i, inp in enumerate(self.inputs):
            if inp.sp_ecdh_shares:
                for _, share in inp.sp_ecdh_shares.items():
                    if len(share) != 33:
                        raise FatalPSBTIssue(
                            "Input #%d ECDH share wrong size (%d bytes, expected 33)"
                            % (i, len(share))
                        )
            if inp.sp_dleq_proofs:
                for _, proof in inp.sp_dleq_proofs.items():
                    if len(proof) != 64:
                        raise FatalPSBTIssue(
                            "Input #%d DLEQ proof wrong size (%d bytes, expected 64)"
                            % (i, len(proof))
                        )

        # TX_MODIFIABLE must be cleared when output scripts are finalized
        for outp in self.outputs:
            if outp.sp_v0_info and outp.script:
                if self.txn_modifiable is not None and self.txn_modifiable != 0:
                    raise FatalPSBTIssue(
                        "TX_MODIFIABLE not cleared but SP output script is set"
                    )

    def _validate_input_eligibility(self):
        """
        Validate input constraints for silent payments (BIP-375)

        Raises FatalPSBTIssue if any input constraints are violated
        """
        for i, inp in enumerate(self.inputs):
            if not inp.utxo_spk:
                continue

            spk = inp.utxo_spk
            # No segwit v>1 inputs when SP outputs present
            if len(spk) >= 2 and 0x52 <= spk[0] <= 0x60:
                witness_version = spk[0] - 0x50
                raise FatalPSBTIssue(
                    "BIP-375 violation: Input #%d spends Segwit v%d output. "
                    "Silent payment outputs cannot be mixed with Segwit v>1 inputs."
                    % (i, witness_version)
                )

            # SIGHASH_ALL required when SP outputs present
            if inp.sighash is not None and inp.sighash not in (
                SIGHASH_ALL,
                SIGHASH_DEFAULT,
            ):
                raise FatalPSBTIssue(
                    "BIP-375 violation: Input #%d uses sighash 0x%x. "
                    "Silent payments require SIGHASH_ALL." % (i, inp.sighash)
                )

    def _validate_ecdh_coverage(self):
        """
        Validate ECDH share coverage and DLEQ proof correctness (BIP-375)
        
        Raises FatalPSBTIssue if any ECDH / DLEQ requirements are violated
        """
        scan_keys = self._get_silent_payment_scan_keys()
        if not scan_keys:
            return

        for scan_key in scan_keys:
            has_global = (
                self.sp_global_ecdh_shares and scan_key in self.sp_global_ecdh_shares
            )
            has_input = any(
                inp.sp_ecdh_shares and scan_key in inp.sp_ecdh_shares
                for inp in self.inputs
            )

            # Check if any output with this scan pk has a computed script
            scan_key_has_script = any(
                outp.sp_v0_info and outp.sp_v0_info[:33] == scan_key and outp.script
                for outp in self.outputs
            )

            if scan_key_has_script and not has_global and not has_input:
                raise FatalPSBTIssue(
                    "SP output script set but no ECDH share for scan key"
                )

            # Verify global DLEQ proof
            if has_global:
                if (
                    not self.sp_global_dleq_proofs
                    or scan_key not in self.sp_global_dleq_proofs
                ):
                    raise FatalPSBTIssue("Global ECDH share missing DLEQ proof")

                ecdh_share = self.sp_global_ecdh_shares[scan_key]
                proof = self.sp_global_dleq_proofs[scan_key]

                # Sum all eligible input pubkeys
                pubkeys = []
                for inp in self.inputs:
                    pk = self._pubkey_from_input(inp)
                    if pk:
                        pubkeys.append(pk)
                if not pubkeys:
                    raise FatalPSBTIssue("No public keys found for DLEQ verification")
                combined_pk = _combine_pubkeys(pubkeys)

                if not verify_dleq_proof(combined_pk, scan_key, ecdh_share, proof):
                    raise FatalPSBTIssue("Global DLEQ proof verification failed")

            # Verify per-input coverage and DLEQ proofs
            if scan_key_has_script and not has_global:
                for i, inp in enumerate(self.inputs):
                    eligible = self._is_input_eligible(inp)
                    has_share = inp.sp_ecdh_shares and scan_key in inp.sp_ecdh_shares

                    if not eligible and has_share:
                        raise FatalPSBTIssue(
                            "Input #%d has ECDH share but is ineligible" % i
                        )
                    if eligible and not has_share:
                        raise FatalPSBTIssue(
                            "Eligible input #%d missing ECDH share" % i
                        )

                    if has_share:
                        if not inp.sp_dleq_proofs or scan_key not in inp.sp_dleq_proofs:
                            raise FatalPSBTIssue(
                                "Input #%d ECDH share missing DLEQ proof" % i
                            )

                        pk = self._pubkey_from_input(inp)
                        if not pk:
                            raise FatalPSBTIssue(
                                "Input #%d missing public key for DLEQ verification" % i
                            )

                        ecdh_share = inp.sp_ecdh_shares[scan_key]
                        proof = inp.sp_dleq_proofs[scan_key]
                        if not verify_dleq_proof(pk, scan_key, ecdh_share, proof):
                            raise FatalPSBTIssue(
                                "Input #%d DLEQ proof verification failed" % i
                            )

    def _is_ecdh_coverage_complete(self):
        """
        Check if all eligible inputs have ECDH shares for all scan keys

        Returns:
            bool: True if coverage is complete, False if any eligible input is missing a share for any scan key
        """
        scan_keys = self._get_silent_payment_scan_keys()
        if not scan_keys:
            return True

        for scan_key in scan_keys:
            if self.sp_global_ecdh_shares and scan_key in self.sp_global_ecdh_shares:
                continue
            # Check per-input: every eligible input must have a share
            for inp in self.inputs:
                if self._is_input_eligible(inp):
                    if not inp.sp_ecdh_shares or scan_key not in inp.sp_ecdh_shares:
                        return False
        return True


    # -----------------------------------------------------------------------------
    # Process Output Functions
    # -----------------------------------------------------------------------------

    def has_silent_payment_outputs(self):
        """
        Check if PSBT contains any silent payment outputs

        Returns:
            bool: True if any output has PSBT_OUT_SP_V0_INFO field
        """
        for outp in self.outputs:
            if outp.sp_v0_info:
                return True
        return False

    def _compute_and_store_ecdh_shares(self, sv):
        """
        Compute ECDH shares and DLEQ proofs for our inputs, store in PSBT fields
         
        Notes:
            For single-signer: sum all private keys, store as global fields.
            For multi-signer: store per-input for owned inputs. (Contribute shares)
            Sets self.sp_all_inputs_ours for callers.

        Returns:
            bool: True if shares were computed, False if we have no signable inputs
        """
        # Collect per-input private keys for eligible inputs we own.
        # Track foreign ownership: if _derive_input_privkey returns None for an input
        # that has derivation paths, that input belongs to another signer.
        has_foreign = False
        input_privkeys = []  # list of (inp, privkey_int)
        for inp in self.inputs:
            if not inp.sp_idxs or not self._is_input_eligible(inp):
                continue

            privkey_int = self._derive_input_privkey(inp, sv)
            if privkey_int:
                input_privkeys.append((inp, privkey_int))
            elif inp.taproot_subpaths or inp.subpaths:
                has_foreign = True

        # FIXME: is this the right approach?
        # Detect foreign eligible inputs (different XFP, no sp_idxs) 
        if not has_foreign:
            for inp in self.inputs:
                if inp.sp_idxs:
                    continue
                if self._is_input_eligible(inp) and self._pubkey_from_input(inp):
                    has_foreign = True
                    break

        if not input_privkeys:
            return False

        self.sp_all_inputs_ours = not has_foreign
        all_inputs_ours = self.sp_all_inputs_ours
        
        scan_keys = self._get_silent_payment_scan_keys()
        if not scan_keys:
            return False

        for scan_key in scan_keys:
            if all_inputs_ours:
                # Single-signer: sum all private keys, one global ECDH share and DLEQ proofs
                combined_sk = 0
                for _, privkey_int in input_privkeys:
                    combined_sk = (combined_sk + privkey_int) % SECP256K1_ORDER

                ecdh_share = _compute_ecdh_share(combined_sk, scan_key)
                dleq_proof = generate_dleq_proof(combined_sk, scan_key)

                if self.sp_global_ecdh_shares is None:
                    self.sp_global_ecdh_shares = {}
                if self.sp_global_dleq_proofs is None:
                    self.sp_global_dleq_proofs = {}
                self.sp_global_ecdh_shares[scan_key] = ecdh_share
                self.sp_global_dleq_proofs[scan_key] = dleq_proof
            else:
                # Multi-signer: per-input ECDH shares and DLEQ proofs for owned inputs
                for inp, privkey_int in input_privkeys:
                    ecdh_share = _compute_ecdh_share(privkey_int, scan_key)
                    dleq_proof = generate_dleq_proof(privkey_int, scan_key)

                    if inp.sp_ecdh_shares is None:
                        inp.sp_ecdh_shares = {}
                    if inp.sp_dleq_proofs is None:
                        inp.sp_dleq_proofs = {}
                    inp.sp_ecdh_shares[scan_key] = ecdh_share
                    inp.sp_dleq_proofs[scan_key] = dleq_proof

        return True

    def _iter_input_xfp_paths(self, inp):
        """
        Iterate over all BIP32 derivation paths for an input, yielding parsed xfp_path tuples

        Note:
            For taproot inputs, yields paths from taproot_subpaths (path_coords[2]).
            For non-taproot inputs, yields paths from subpaths (path_coords).

        Returns:
            Generator of parsed xfp_path tuples for all derivation paths in the input
        """
        if inp.taproot_subpaths:
            for _, path_coords in inp.taproot_subpaths:
                yield self.parse_xfp_path(path_coords[2])
        elif inp.subpaths:
            for _, path_coords in inp.subpaths:
                yield self.parse_xfp_path(path_coords)

    def _path_to_privkey(self, xfp_path, sv):
        """
        Derive private key from a parsed xfp_path tuple
        
        Returns:
            int: The derived private key as an integer
        """
        node = sv.derive_path(keypath_to_str(xfp_path, skip=1), register=False)
        return int.from_bytes(node.privkey(), "big")

    def _derive_input_privkey(self, inp, sv):
        """
        Derive the BIP-352 contributing private key for an eligible input

        Note:
            If inp.sp_tweak is set (BIP-376), derives from sp_spend_bip32_derivation
                and applies the tweak: d_k = d_spend + t_k (mod n)
            For taproot inputs, uses the internal key's derivation path (ik_idx), XFP-checked
            For non-taproot inputs, uses the first matching BIP32 derivation path

        Returns:
            int | None: The derived private key as an integer, or None if not eligible
        """
        privkey_int = None

        if inp.sp_tweak and inp.sp_spend_bip32_derivation:
            _, val_coords = inp.sp_spend_bip32_derivation
            xfp_path = self.parse_xfp_path(val_coords)
            if xfp_path[0] == self.my_xfp:
                privkey_int = self._path_to_privkey(xfp_path, sv)
                privkey_int = _compute_silent_payment_spending_privkey(
                    privkey_int.to_bytes(32, 'big'), inp.sp_tweak
                )
                # BIP-352: normalize to even-Y so contributing privkey matches
                # 0x02||x(P_k) convention used by _pubkey_from_input
                G = ngu.secp256k1.generator()
                P_k = ngu.secp256k1.ec_pubkey_tweak_mul(G, privkey_int.to_bytes(32, 'big'))
                if P_k[0] == 0x03:
                    privkey_int = SECP256K1_ORDER - privkey_int
        else:
            spk = inp.utxo_spk
            if spk and _is_p2tr(spk):
                if inp.ik_idx is not None and inp.taproot_subpaths:
                    _, path_coords = inp.taproot_subpaths[inp.ik_idx[0]]
                    xfp_path = self.parse_xfp_path(path_coords[2])
                    if xfp_path[0] == self.my_xfp:
                        privkey_int = self._path_to_privkey(xfp_path, sv)
                        privkey_int = self._tweak_p2tr_privkey(privkey_int, inp)
            else:
                for xfp_path in self._iter_input_xfp_paths(inp):
                    if xfp_path[0] == self.my_xfp:
                        privkey_int = self._path_to_privkey(xfp_path, sv)
                        break

        return privkey_int

    def _get_outpoints(self):
        """
        Get a list of outpoints (txid, vout) for all inputs

        Returns:
            list[tuple[bytes, bytes]]: A list of tuples containing the transaction ID and output index for each input
        """
        outpoints = []
        for inp in self.inputs:
            if inp.previous_txid and inp.prevout_idx is not None:
                outpoints.append(
                    (self.get(inp.previous_txid), self.get(inp.prevout_idx))
                )
            else:
                raise FatalPSBTIssue("Missing outpoint for silent payment input")
        if not outpoints:
            raise FatalPSBTIssue(
                "No eligible inputs for silent payment output computation"
            )
        return outpoints

    def _compute_silent_payment_output_scripts(self):
        """
        Compute and set the scriptPubKey for each silent payment output based on the ECDH shares and input pubkeys.

        Note: All validations must be done before calling this function.
            
        No return value; modifies self.outputs in-place.
        """
        outpoints = self._get_outpoints()

        # Track k per scan key
        scan_key_k = {}

        for out_idx, outp in enumerate(self.outputs):
            if not outp.sp_v0_info:
                continue

            scan_key = outp.sp_v0_info[:33]
            B_spend = outp.sp_v0_info[33:66]
            k = scan_key_k.get(scan_key, 0)

            ecdh_share, summed_pubkey = self._get_ecdh_and_pubkey(scan_key)
            if not ecdh_share or not summed_pubkey:
                raise FatalPSBTIssue("Missing ECDH share for output #%d" % out_idx)

            computed = _compute_silent_payment_output_script(
                outpoints, summed_pubkey, ecdh_share, B_spend, k
            )

            if outp.script:
                existing = self.get(outp.script) if isinstance(outp.script, tuple) else outp.script
                if existing != computed:
                    raise FatalPSBTIssue("SP output #%d: output script mismatch" % out_idx)

            outp.script = computed
            scan_key_k[scan_key] = k + 1

    def _get_ecdh_and_pubkey(self, scan_key):
        """
        Get ECDH share and summed pubkey for a given scan key
        
        Returns:
            (ecdh_share_bytes, summed_pubkey_bytes) or (None, None)
        """
        # Global share: return ECDH share directly, sum all eligible input pubkeys
        if self.sp_global_ecdh_shares and scan_key in self.sp_global_ecdh_shares:
            ecdh_share = self.sp_global_ecdh_shares[scan_key]
            # Sum all eligible input pubkeys
            pubkeys = []
            for inp in self.inputs:
                if self._is_input_eligible(inp):
                    pk = self._pubkey_from_input(inp)
                    if pk:
                        pubkeys.append(pk)
            if pubkeys:
                return ecdh_share, _combine_pubkeys(pubkeys)
            return None, None

        # Per-input shares: combine shares and pubkeys from eligible inputs
        combined_ecdh = None
        pubkeys = []
        for inp in self.inputs:
            if inp.sp_ecdh_shares and scan_key in inp.sp_ecdh_shares:
                ecdh_share = inp.sp_ecdh_shares[scan_key]
                if combined_ecdh is None:
                    combined_ecdh = ecdh_share
                else:
                    combined_ecdh = ngu.secp256k1.ec_pubkey_combine(combined_ecdh, ecdh_share)
                if self._is_input_eligible(inp):
                    pk = self._pubkey_from_input(inp)
                    if pk:
                        pubkeys.append(pk)

        if combined_ecdh and pubkeys:
            return combined_ecdh, _combine_pubkeys(pubkeys)

        return None, None

    def _get_silent_payment_scan_keys(self):
        """
        Extract unique scan keys from silent payment outputs

        Returns:
            list: List of unique scan_key bytes (33 bytes each)
        """
        scan_keys = set()
        for outp in self.outputs:
            if outp.sp_v0_info:
                scan_key = outp.sp_v0_info[:33]
                scan_keys.add(scan_key)

        return list(scan_keys)
