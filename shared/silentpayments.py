# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# silentpayments.py - BIP-352/BIP-375
#
# Consolidates cryptographic primitives and PSBT handling logic for Silent Payments
#
import ngu
from dleq import generate_dleq_proof, verify_dleq_proof
from exceptions import FatalPSBTIssue
from precomp_tag_hash import BIP352_SHARED_SECRET_TAG_H, BIP352_INPUTS_TAG_H
from serializations import SIGHASH_ALL, SIGHASH_DEFAULT
from ubinascii import unhexlify as a2b_hex
from utils import keypath_to_str

G = ngu.secp256k1.generator()
# BIP-341 NUMS point (Nothing Up My Sleeve) - x-only (32-byte)
NUMS_H = a2b_hex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
SECP256K1_ORDER = ngu.secp256k1.curve_order_int()

# -----------------------------------------------------------------------------
# Silent Payments Cryptographic Primitives
# -----------------------------------------------------------------------------


def _combine_pubkeys(pubkeys):
    """
    Combine a list of public keys into a single public key

    Args:
        pubkeys: List of public keys to combine (33-byte compressed)

    Returns:
        bytes: Combined public key (33-byte compressed)
    """
    if len(pubkeys) == 1:
        return pubkeys[0]
    return ngu.secp256k1.ec_pubkey_combine(pubkeys)


def _compute_ecdh_share(a_sum_bytes, B_scan_bytes):
    """
    Compute ECDH share (partial shared secret)

    Formula: ecdh_share = a_sum * B_scan

    Args:
        a_sum_bytes: Combined private key (32-byte scalar)
        B_scan_bytes: Scan public key (33-byte compressed)

    Returns:
        bytes: ECDH share point (33-byte compressed)
    """
    return ngu.secp256k1.ec_pubkey_tweak_mul(B_scan_bytes, a_sum_bytes)


def _compute_input_hash(outpoints, A_sum_bytes):
    """
    Compute BIP-352 input hash

    Formula: input_hash = hash_BIP0352/Inputs(smallest_outpoint || A_sum)

    Args:
        outpoints: List of (txid, vout) tuples, where txid is 32-byte and vout is 4-byte little-endian
        A_sum_bytes: Sum of all eligible input public keys (33-byte compressed)

    Returns:
        bytes: Input hash (32-byte scalar)
    """
    smallest = min(outpoints, key=lambda x: x[0] + x[1])
    msg = smallest[0] + smallest[1] + A_sum_bytes
    input_hash_bytes = ngu.hash.sha256t(BIP352_INPUTS_TAG_H, msg, True)
    input_hash_int = int.from_bytes(input_hash_bytes, "big")
    if not (0 < input_hash_int < SECP256K1_ORDER):
        raise ValueError("Invalid input hash: not in valid scalar range")
    return input_hash_int.to_bytes(32, "big")


def _compute_shared_secret_tweak(shared_secret_bytes, k):
    """
    Compute BIP-352 shared secret tweak

    Formula: t_k = hash_BIP0352/SharedSecret(serP(shared_secret) || ser_32(k))

    Args:
        shared_secret_bytes: Shared secret point (33-byte compressed)
        k: Output index per scan key group (int)

    Returns:
        bytes: Shared secret tweak (32-byte scalar)
    """
    msg = shared_secret_bytes + k.to_bytes(4, "big")
    tweak_bytes = ngu.hash.sha256t(BIP352_SHARED_SECRET_TAG_H, msg, True)
    tweak_int = int.from_bytes(tweak_bytes, "big")
    if not (0 < tweak_int < SECP256K1_ORDER):
        raise ValueError("Invalid shared secret tweak: not in valid scalar range")
    return tweak_int.to_bytes(32, "big")


def _compute_silent_payment_output_script(outpoints, A_sum_bytes, ecdh_share_bytes, B_spend_bytes, k):
    """
    Compute the P2TR scriptPubKey for silent payment

    Formula: P_k = B_spend + t_k * G

    Args:
        outpoints: List of (txid, vout) tuples from eligible inputs
        A_sum_bytes: Sum of eligible input public keys (33-byte compressed)
        ecdh_share_bytes: ECDH share point (33-byte compressed)
        B_spend_bytes: Recipient spend public key (33-byte compressed)
        k: Output index per scan key group (int)

    Returns:
        bytes: P2TR scriptPubKey (OP_1 <32-byte x-only pubkey>)
    """
    input_hash_bytes = _compute_input_hash(outpoints, A_sum_bytes)
    shared_secret_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(ecdh_share_bytes, input_hash_bytes)
    tweak_bytes = _compute_shared_secret_tweak(shared_secret_bytes, k)
    # Derive output pubkey: P_k = B_spend + t_k * G
    tweak_point = ngu.secp256k1.ec_pubkey_tweak_mul(G, tweak_bytes)
    output_pubkey = ngu.secp256k1.ec_pubkey_combine([B_spend_bytes, tweak_point])
    x_only = output_pubkey[1:]
    return b"\x51\x20" + x_only


# -----------------------------------------------------------------------------
# Input Eligibility
# -----------------------------------------------------------------------------


def _is_p2pkh(spk):
    # OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return (
        len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9 and spk[2] == 0x14 and spk[-2] == 0x88 and spk[-1] == 0xAC
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
    Mixin class for psbtObject to handle Silent Payments logic

    This class assumes it is mixed into psbtObject and has access to psbt as self
    """

    def _process_silent_payments(self, sv):
        """
        Core SP workflow: validate, compute shares, compute scripts

        Returns:
            bool: True if output scripts were computed
        """
        if not self.has_silent_payment_outputs():
            return
        self._validate_psbt_structure()
        self._validate_input_eligibility()
        self._validate_ecdh_coverage()

        if not self._compute_and_store_ecdh_shares(sv):
            return False

        if self._is_ecdh_coverage_complete():
            self._compute_silent_payment_output_scripts()
            return True
        return False

    # -----------------------------------------------------------------------------
    # Input Helper Functions
    # -----------------------------------------------------------------------------

    def _get_ecdh_and_pubkey(self, scan_key):
        """
        Get combined ECDH share and summed pubkey for a given scan key

        Returns:
            tuple: (ecdh_share_bytes, summed_pubkey_bytes) or (None, None)
        """
        # Global share: return ECDH share directly, sum all eligible input pubkeys
        if self.sp_global_ecdh_shares and scan_key in self.sp_global_ecdh_shares:
            ecdh_share = self.sp_global_ecdh_shares[scan_key]
            pubkeys = []
            for inp in self.inputs:
                if self._is_input_eligible(inp):
                    pk = self._pubkey_from_input(inp)
                    if pk:
                        pubkeys.append(pk)
            if pubkeys:
                return ecdh_share, _combine_pubkeys(pubkeys)

        # Per-input shares: combine EDCH shares and sum all eligible input pubkeys
        combined_ecdh = None
        pubkeys = []
        for inp in self.inputs:
            if inp.sp_ecdh_shares and scan_key in inp.sp_ecdh_shares:
                share = inp.sp_ecdh_shares[scan_key]
                if combined_ecdh is None:
                    combined_ecdh = share
                else:
                    combined_ecdh = ngu.secp256k1.ec_pubkey_combine([combined_ecdh, share])
                pk = self._pubkey_from_input(inp)
                if pk:
                    pubkeys.append(pk)

        if combined_ecdh and pubkeys:
            return combined_ecdh, _combine_pubkeys(pubkeys)
        return None, None

    def _is_input_eligible(self, input):
        """Check if input is eligible for silent payments per BIP-352"""
        spk = input.utxo_spk
        if not spk:
            return False

        if not (_is_p2pkh(spk) or _is_p2wpkh(spk) or _is_p2tr(spk) or _is_p2sh(spk)):
            return False

        if _is_p2tr(spk):
            if input.taproot_internal_key:
                tap_ik = self.get(input.taproot_internal_key)
                if tap_ik == NUMS_H:
                    return False

        if _is_p2sh(spk):
            if input.redeem_script:
                rs = self.get(input.redeem_script)
                if not _is_p2wpkh(rs):
                    return False
            else:
                return False
        return True

    def _pubkey_from_input(self, input):
        """
        Extract the contributing public key from an input

        Note:
            P2TR: use PSBT_IN_WITNESS_UTXO to fetch x-only compressed pubkey
            non-taproot: use BIP32 derivation pubkey from subpaths

        Returns:
            bytes: Input public key (33-byte compressed) or None if not found
        """
        spk = input.utxo_spk
        if spk and _is_p2tr(spk):
            return b"\x02" + spk[2:34]
        if input.subpaths:
            for pk_coords, _ in input.subpaths:
                pk = self.get(pk_coords)
                if len(pk) == 33:
                    return pk
        return None

    # -----------------------------------------------------------------------------
    # Validation Functions
    # -----------------------------------------------------------------------------

    def _is_ecdh_coverage_complete(self):
        """
        Check if all eligible inputs have ECDH shares for all scan keys

        Returns:
            bool: True if coverage is complete
                  False if any eligible input is missing a share for any scan key
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
                raise FatalPSBTIssue("Output #%d must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO" % i)

            if has_sp_label and not has_sp_info:
                raise FatalPSBTIssue("Output #%d has SP label but missing SP_V0_INFO" % i)

            if has_sp_info:
                if len(outp.sp_v0_info) != 66:
                    raise FatalPSBTIssue(
                        "Output #%d SP_V0_INFO wrong size (%d bytes, expected 66)" % (i, len(outp.sp_v0_info))
                    )

        # Validate ECDH share sizes (33 bytes) and DLEQ proof sizes (64 bytes)
        if self.sp_global_ecdh_shares:
            for _, share in self.sp_global_ecdh_shares.items():
                if len(share) != 33:
                    raise FatalPSBTIssue("Global ECDH share wrong size (%d bytes, expected 33)" % len(share))

        if self.sp_global_dleq_proofs:
            for _, proof in self.sp_global_dleq_proofs.items():
                if len(proof) != 64:
                    raise FatalPSBTIssue("Global DLEQ proof wrong size (%d bytes, expected 64)" % len(proof))

        for i, inp in enumerate(self.inputs):
            if inp.sp_ecdh_shares:
                for _, share in inp.sp_ecdh_shares.items():
                    if len(share) != 33:
                        raise FatalPSBTIssue(
                            "Input #%d ECDH share wrong size (%d bytes, expected 33)" % (i, len(share))
                        )
            if inp.sp_dleq_proofs:
                for _, proof in inp.sp_dleq_proofs.items():
                    if len(proof) != 64:
                        raise FatalPSBTIssue(
                            "Input #%d DLEQ proof wrong size (%d bytes, expected 64)" % (i, len(proof))
                        )

        # TX_MODIFIABLE must be cleared when output scripts are finalized
        for outp in self.outputs:
            if outp.sp_v0_info and outp.script:
                if self.txn_modifiable is not None and self.txn_modifiable != 0:
                    raise FatalPSBTIssue("TX_MODIFIABLE not cleared but SP output script is set")

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
                    "Silent payment outputs cannot be mixed with Segwit v>1 inputs." % (i, witness_version)
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

        Raises FatalPSBTIssue if any ECDH share / DLEQ requirements are violated
        """
        scan_keys = self._get_silent_payment_scan_keys()
        if not scan_keys:
            return

        for scan_key in scan_keys:
            has_global = self.sp_global_ecdh_shares and scan_key in self.sp_global_ecdh_shares
            has_input = any(inp.sp_ecdh_shares and scan_key in inp.sp_ecdh_shares for inp in self.inputs)

            # Check if any output with this scan pk has a computed script
            scan_key_has_script = any(
                outp.sp_v0_info and outp.sp_v0_info[:33] == scan_key and outp.script for outp in self.outputs
            )

            if scan_key_has_script and not has_global and not has_input:
                raise FatalPSBTIssue("SP output script set but no ECDH share for scan key")

            # Verify global DLEQ proof
            if has_global:
                if not self.sp_global_dleq_proofs or scan_key not in self.sp_global_dleq_proofs:
                    raise FatalPSBTIssue("Global ECDH share missing DLEQ proof")

                ecdh_share = self.sp_global_ecdh_shares[scan_key]
                proof = self.sp_global_dleq_proofs[scan_key]

                # Sum all eligible input pubkeys
                pubkeys = []
                for inp in self.inputs:
                    if not self._is_input_eligible(inp):
                        continue
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
                        raise FatalPSBTIssue("Input #%d has ECDH share but is ineligible" % i)
                    if eligible and not has_share:
                        raise FatalPSBTIssue("Eligible input #%d missing ECDH share" % i)

                    if has_share:
                        if not inp.sp_dleq_proofs or scan_key not in inp.sp_dleq_proofs:
                            raise FatalPSBTIssue("Input #%d ECDH share missing DLEQ proof" % i)

                        pk = self._pubkey_from_input(inp)
                        if not pk:
                            raise FatalPSBTIssue("Input #%d missing public key for DLEQ verification" % i)

                        ecdh_share = inp.sp_ecdh_shares[scan_key]
                        proof = inp.sp_dleq_proofs[scan_key]
                        if not verify_dleq_proof(pk, scan_key, ecdh_share, proof):
                            raise FatalPSBTIssue("Input #%d DLEQ proof verification failed" % i)

    # -----------------------------------------------------------------------------
    # Modify PSBT Field Functions
    # -----------------------------------------------------------------------------

    def _compute_and_store_ecdh_shares(self, sv):
        """
        Compute ECDH shares and DLEQ proofs for our inputs, store in PSBT fields

        Notes:
            Sets self.sp_all_inputs_ours for callers

        Returns:
            bool: True if shares were computed
                  False if we have no signable inputs
        """
        # Collect per-input private keys for eligible inputs we own
        # Track foreign ownership: if _derive_input_privkey returns None for an input
        # that has derivation paths, that input belongs to another signer
        has_foreign = False
        input_material = []  # list of (inp, privkey_int)
        for inp in self.inputs:
            if not inp.sp_idxs or not self._is_input_eligible(inp):
                continue

            input_sk = self._derive_input_privkey(inp, sv)
            if input_sk:
                input_material.append((inp, input_sk))
            elif inp.taproot_subpaths or inp.subpaths:
                has_foreign = True

        # Detect foreign eligible inputs (different XFP, no sp_idxs)
        if not has_foreign:
            for inp in self.inputs:
                if inp.sp_idxs:
                    continue
                if self._is_input_eligible(inp) and self._pubkey_from_input(inp):
                    has_foreign = True
                    break

        if not input_material:
            return False

        self.sp_all_inputs_ours = not has_foreign
        all_inputs_ours = self.sp_all_inputs_ours

        scan_keys = self._get_silent_payment_scan_keys()
        if not scan_keys:
            return False

        for scan_key in scan_keys:
            if all_inputs_ours:
                # Single-signer: combine all input private keys, one global ECDH share and DLEQ proofs
                combined_sk = 0
                for _, input_sk in input_material:
                    input_sk_int = int.from_bytes(input_sk, "big")
                    combined_sk = (combined_sk + input_sk_int) % SECP256K1_ORDER

                ecdh_share = _compute_ecdh_share(combined_sk.to_bytes(32, "big"), scan_key)
                dleq_proof = generate_dleq_proof(combined_sk.to_bytes(32, "big"), scan_key)

                self.sp_global_ecdh_shares = self.sp_global_ecdh_shares or {}
                self.sp_global_dleq_proofs = self.sp_global_dleq_proofs or {}
                self.sp_global_ecdh_shares[scan_key] = ecdh_share
                self.sp_global_dleq_proofs[scan_key] = dleq_proof
            else:
                # Multi-signer: per-input ECDH shares and DLEQ proofs for owned inputs
                for inp, input_sk in input_material:
                    ecdh_share = _compute_ecdh_share(input_sk, scan_key)
                    dleq_proof = generate_dleq_proof(input_sk, scan_key)

                    inp.sp_ecdh_shares = inp.sp_ecdh_shares or {}
                    inp.sp_dleq_proofs = inp.sp_dleq_proofs or {}
                    inp.sp_ecdh_shares[scan_key] = ecdh_share
                    inp.sp_dleq_proofs[scan_key] = dleq_proof
        return True

    def _compute_silent_payment_output_scripts(self):
        """
        Compute and set the scriptPubKey for each silent payment output

        Note: All validations "must" be done before calling this function

        No return value; modifies self.outputs in-place
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

            outp.script = _compute_silent_payment_output_script(outpoints, summed_pubkey, ecdh_share, B_spend, k)
            scan_key_k[scan_key] = k + 1

    # -----------------------------------------------------------------------------
    # Utility Functions
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

    def _get_outpoints(self):
        """
        Get a list of outpoints (txid, vout) for all inputs

        Returns:
            list: Outpoints as (txid, vout) tuples
        """
        outpoints = []
        for inp in self.inputs:
            if inp.previous_txid and inp.prevout_idx is not None:
                outpoints.append((self.get(inp.previous_txid), self.get(inp.prevout_idx)))
            else:
                raise FatalPSBTIssue("Missing outpoint for silent payment input")
        if not outpoints:
            raise FatalPSBTIssue("Did not find any outpoints")
        return outpoints

    def _get_silent_payment_scan_keys(self):
        """
        Extract unique scan keys from silent payment outputs

        Returns:
            list: Unique scan public keys (33-byte compressed)
        """
        scan_keys = set()
        for outp in self.outputs:
            if outp.sp_v0_info:
                scan_key = outp.sp_v0_info[:33]
                scan_keys.add(scan_key)
        return list(scan_keys)

    # -----------------------------------------------------------------------------
    # Key Derivation Functions
    # -----------------------------------------------------------------------------

    def _derive_input_privkey(self, input, sv):
        """
        Derive the contributing private key for an eligible input

        Note:
            For taproot inputs, uses the internal key's derivation path (ik_idx), XFP-checked
            For non-taproot inputs, uses the first matching BIP32 derivation path

        Returns:
            bytes: Derived private key as (32-byte scalar) or None if not eligible
        """
        # TODO: BIP-376 sp_spend_derivation should go here
        spk = input.utxo_spk
        if spk and _is_p2tr(spk):
            if input.ik_idx is not None and input.taproot_subpaths:
                _, path_coords = input.taproot_subpaths[input.ik_idx]
                xfp_path = self.parse_xfp_path(path_coords[2])
                if xfp_path[0] == self.my_xfp:
                    return self._path_to_privkey(xfp_path, sv)
        else:
            for xfp_path in self._iter_input_xfp_paths(input):
                if xfp_path[0] == self.my_xfp:
                    return self._path_to_privkey(xfp_path, sv)
        return None

    def _iter_input_xfp_paths(self, input):
        """
        Iterate over all BIP32 derivation paths for an input, yielding parsed xfp_path tuples

        Note:
            For taproot inputs, yields paths from taproot_subpaths (path_coords[2])
            For non-taproot inputs, yields paths from subpaths (path_coords)

        Returns:
            generator: Parsed xfp_path tuples for all derivation paths in the input
        """
        if input.taproot_subpaths:
            for _, path_coords in input.taproot_subpaths:
                yield self.parse_xfp_path(path_coords[2])
        elif input.subpaths:
            for _, path_coords in input.subpaths:
                yield self.parse_xfp_path(path_coords)

    def _path_to_privkey(self, xfp_path, sv):
        """
        Derive private key from a parsed xfp_path tuple

        Returns:
            bytes: Derived private key (32-byte scalar)
        """
        node = sv.derive_path(keypath_to_str(xfp_path, skip=1), register=False)
        return node.privkey()
