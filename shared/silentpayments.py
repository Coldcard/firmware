# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# silentpayments.py - BIP-352/BIP-375 Silent Payment Logic
#
# Consolidates cryptographic primitives and PSBT handling logic for Silent Payments.
#

import ckcc
import ngu
from ubinascii import hexlify as b2a_hex
from exceptions import FatalPSBTIssue
from precomp_tag_hash import BIP352_SHARED_SECRET_TAG_H, BIP352_INPUTS_TAG_H, BIP352_LABEL_TAG_H
from dleq import generate_dleq_proof, verify_dleq_proof

# print some things, sometimes
DEBUG = ckcc.is_simulator()

# -----------------------------------------------------------------------------
# Silent Payments Cryptographic Primitives
# -----------------------------------------------------------------------------

def apply_label_to_spend_key(spend_pubkey_bytes, scan_privkey_bytes, label):
    """
    Apply BIP-352 label tweak to spend key
    
    Labels allow a single silent payment address to generate multiple
    independent addresses (e.g., for different purposes or change).
    
    BIP-352 formula: B_m = B_spend + hash_BIP0352/Label(b_scan || m)*G
    
    Args:
        spend_pubkey_bytes: Base spend public key (33 bytes compressed)
        scan_privkey_bytes: Scan private key (32 bytes) - needed to compute label tweak
        label: Label integer (0 for change, >0 for other purposes)
    
    Returns:
        bytes: Labeled spend public key (33 bytes compressed)
    
    Raises:
        ValueError: If keys are invalid
    """
    # Validate spend public key
    try:
        ngu.secp256k1.pubkey(spend_pubkey_bytes)
    except:
        raise ValueError("Invalid spend public key")
    
    # Compute label tweak: hash_BIP0352/Label(b_scan || m)
    # BIP-352 uses tagged hash for labels
    msg = scan_privkey_bytes + label.to_bytes(4, 'big')
    tweak_bytes = ngu.hash.sha256t(BIP352_LABEL_TAG_H, msg, True)

    # Reduce by curve order
    SECP256K1_ORDER = ngu.secp256k1.curve_order_int()
    tweak_scalar = int.from_bytes(tweak_bytes, 'big') % SECP256K1_ORDER
    tweak_bytes = tweak_scalar.to_bytes(32, 'big')

    # Compute tweak*G
    G_bytes = ngu.secp256k1.generator()
    tweak_point = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, tweak_bytes)
    
    # Apply tweak: B_m = B_spend + tweak*G
    labeled_spend_pubkey = ngu.secp256k1.ec_pubkey_combine(spend_pubkey_bytes, tweak_point)
    
    return labeled_spend_pubkey


def compute_ecdh_share(privkey_int, scan_pubkey_bytes):
    """
    Compute ECDH share for BIP-352 silent payments
    
    Formula: ecdh_share = privkey * scan_pubkey
    
    Args:
        privkey_int: Private key as integer
        scan_pubkey_bytes: Scan public key (33 bytes compressed)
    
    Returns:
        bytes: ECDH share as compressed public key (33 bytes)
    """
    # Convert privkey int to bytes (32 bytes, big-endian)
    privkey_bytes = privkey_int.to_bytes(32, 'big')
    
    # Validate scan_pubkey using ngu.secp256k1.pubkey()
    try:
        ngu.secp256k1.pubkey(scan_pubkey_bytes)
    except:
        raise ValueError("Invalid scan public key")
    
    # Compute ECDH share: privkey * scan_pubkey
    # Using new ngu function: ec_pubkey_tweak_mul(pubkey, scalar)
    ecdh_share = ngu.secp256k1.ec_pubkey_tweak_mul(scan_pubkey_bytes, privkey_bytes)
    
    return ecdh_share


def compute_shared_secret_tweak(ecdh_share_bytes, k):
    """
    Compute BIP-352 shared secret tweak for output index k
    
    BIP-352 formula: t_k = hash_BIP0352/SharedSecret(ecdh_share || ser_32(k))
    
    Args:
        ecdh_share_bytes: Combined ECDH share (33 bytes compressed point)
        k: Output index (0-based)
    
    Returns:
        int: Shared secret tweak as scalar (for point multiplication)
    """
    # BIP-352: t_k = hash_BIP0352/SharedSecret(ecdh_share || ser_32(k))
    # Use tagged hash with precomputed tag hash
    # Serialize k as 4-byte big-endian (per BIP-352)
    k_bytes = k.to_bytes(4, 'big')
    
    # Concatenate ecdh_share || k
    msg = ecdh_share_bytes + k_bytes
    
    # Compute tagged hash
    tweak_bytes = ngu.hash.sha256t(BIP352_SHARED_SECRET_TAG_H, msg, True)

    # Convert hash to scalar (reduce by curve order)
    SECP256K1_ORDER = ngu.secp256k1.curve_order_int()
    tweak_scalar = int.from_bytes(tweak_bytes, 'big') % SECP256K1_ORDER

    return tweak_scalar


def compute_input_hash(outpoints, summed_pubkey_bytes):
    """
    Compute BIP-352 input hash
    
    BIP-352 formula: input_hash = hash_BIP0352/Inputs(outpoints || summed_pubkey)
    
    Args:
        outpoints: List of (txid, vout) tuples, where txid is 32 bytes and vout is int
        summed_pubkey_bytes: Sum of all eligible input public keys (33 bytes compressed)
    
    Returns:
        int: Input hash as scalar
    """
    # Sort outpoints lexicographically (by txid, then by vout)
    sorted_outpoints = sorted(outpoints, key=lambda x: (x[0], x[1]))
    
    # Serialize outpoints: for each outpoint, txid (32 bytes) || vout (4 bytes little-endian)
    msg = b''
    for txid, vout in sorted_outpoints:
        msg += txid
        msg += vout
    
    # Append summed public key
    msg += summed_pubkey_bytes
    
    # Compute tagged hash
    input_hash_bytes = ngu.hash.sha256t(BIP352_INPUTS_TAG_H, msg, True)

    # Convert to scalar (reduce by curve order)
    SECP256K1_ORDER = ngu.secp256k1.curve_order_int()
    input_hash_scalar = int.from_bytes(input_hash_bytes, 'big') % SECP256K1_ORDER

    return input_hash_scalar


def combine_pubkeys(pubkeys):
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
    
    combined = pubkeys[0]
    for pk in pubkeys[1:]:
        combined = ngu.secp256k1.ec_pubkey_combine(combined, pk)
    
    return combined


def derive_silent_payment_output_pubkey(spend_pubkey_bytes, ecdh_share_bytes, k, input_hash=None):
    """
    Derive silent payment output public key for output index k
    
    BIP-352 formula: P_k = B_spend + t_k*G
    where t_k = hash_BIP0352/SharedSecret(ecdh_share * input_hash || ser_32(k))
    
    Args:
        spend_pubkey_bytes: Spend public key (33 bytes compressed)
        ecdh_share_bytes: Combined ECDH share (33 bytes compressed)
        k: Output index (0-based)
        input_hash: Optional input hash scalar (int). If provided, multiplies ecdh_share by input_hash
    
    Returns:
        bytes: Output public key (33 bytes compressed)
    
    Raises:
        ValueError: If spend_pubkey_bytes is invalid
    """
    # Validate spend public key
    try:
        ngu.secp256k1.pubkey(spend_pubkey_bytes)
    except:
        raise ValueError("Invalid spend public key")
    
    # Apply input hash if provided (BIP-352: ecdh_share * input_hash)
    if input_hash is not None:
        input_hash_bytes = input_hash.to_bytes(32, 'big') if isinstance(input_hash, int) else input_hash
        ecdh_share_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(ecdh_share_bytes, input_hash_bytes)
    
    # Compute shared secret tweak
    tweak_scalar = compute_shared_secret_tweak(ecdh_share_bytes, k)
    tweak_bytes = tweak_scalar.to_bytes(32, 'big')
    
    # Compute t_k*G using the generator point
    G_bytes = ngu.secp256k1.generator()
    tweak_point = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, tweak_bytes)
    
    # Derive output pubkey: P_k = B_spend + t_k*G
    output_pubkey = ngu.secp256k1.ec_pubkey_combine(spend_pubkey_bytes, tweak_point)
    
    return output_pubkey


def pubkey_to_p2tr_script(pubkey_bytes):
    """
    Convert a public key to P2TR (Taproot) scriptPubKey
    
    BIP-352 requires silent payment outputs to use P2TR (Taproot) format.
    
    Args:
        pubkey_bytes: Public key (33 bytes compressed)
    
    Returns:
        bytes: P2TR scriptPubKey (34 bytes: OP_1 <32-byte x-only pubkey>)
    """
    # Extract x-only pubkey (32 bytes, dropping the 02/03 prefix)
    if len(pubkey_bytes) != 33:
        raise ValueError("Invalid pubkey length")
    
    x_only = pubkey_bytes[1:]  # Drop first byte (02 or 03)
    
    # P2TR scriptPubKey: OP_1 (0x51) followed by 32-byte x-only pubkey
    # Length byte (0x20 = 32) is implicit in the OP_1 push
    return b'\x51\x20' + x_only


# -----------------------------------------------------------------------------
# PSBT Mixin
# -----------------------------------------------------------------------------

class SilentPaymentMixin:
    """
    Mixin class for psbtObject to handle BIP-375 Silent Payment logic.
    
    This class assumes it is mixed into psbtObject and has access to:
    - self.inputs
    - self.outputs
    - self.get()
    - self.my_xfp
    - self.parse_xfp_path()
    - self.sp_global_ecdh_shares
    - self.sp_global_dleq_proofs
    """

    def render_silent_payment_output_string(self, output, tx_out):
        """
        Render a human-readable Silent Payment output string for displaying on screen

        Args:
            output: Output object from self.outputs
            tx_out: Transaction output object

        Returns:
            str: Human-readable Silent Payment output string
        """
        if not output.sp_v0_info:
            raise ValueError("Output is not a silent payment output")

        import chains
        val = ' '.join(chains.current_chain().render_value(tx_out.nValue))
        rendered = '%s\n - to silent payment address -\n%s\n' % (val, self.encode_silent_payment_address(output))

        return rendered


    def encode_silent_payment_address(self, output):
        """
        Encode a human-readable Silent Payment address
        
        Args:
            output: Output object from self.outputs
        
        Returns:
            str: bech32m-encoded Silent Payment address (e.g., "sp1...")
        """
        if not output.sp_v0_info:
            raise ValueError("Output is not a silent payment output")

        scan_key = self.get(output.sp_v0_info)[:33]
        spend_key = self.get(output.sp_v0_info)[33:]

        # Get Silent Payment HRP from current chain
        import chains
        hrp = chains.current_chain().sp_hrp
        return self._encode_silent_payment_address(scan_key, spend_key, hrp=hrp)


    def finalize_silent_payment_outputs(self):
        """
        Final step: combine all ECDH shares and compute output scripts
        
        This should be called by the final signer or a coordinator after
        all partial signatures have been collected and combined.
        
        Raises:
            FatalPSBTIssue: If not ready to finalize
        """
        if not self._is_silent_payment_ready_to_finalize():
            raise FatalPSBTIssue(
                "Cannot finalize Silent Payment outputs: "
                "missing ECDH shares or invalid DLEQ proofs"
            )
        
        # Compute final output scripts
        self._compute_silent_payment_output_scripts()
        
        if DEBUG:
            print("Silent Payment outputs finalized")


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


    def preview_silent_payment_outputs(self):
        """
        Pre-compute Silent Payment output scripts for display during validation
        
        Only works when:
        - Wallet owns all inputs (single signer)
        - Can derive all necessary private keys
        
        This allows showing real addresses in approval UI instead of placeholders.
        
        Returns:
            bool: True if preview succeeded, False otherwise
        """
        if not self.has_silent_payment_outputs():
            return False
        
        # Check if we own all inputs
        if not self._check_all_inputs_owned():
            if DEBUG:
                print("Multi-signer detected - cannot preview SP outputs")
            return False
        
        # Need SensitiveValues context to derive keys
        import stash
        try:
            with stash.SensitiveValues() as sv:
                # Extract scan keys
                scan_keys = self._get_silent_payment_scan_keys()
                
                if not scan_keys:
                    return False
                
                # Compute ECDH shares (same as during signing)
                ecdh_results = self._compute_silent_payment_ecdh_shares(scan_keys, sv)
                
                if not ecdh_results:
                    return False
                
                # Store the computed shares
                self._store_silent_payment_ecdh_shares(ecdh_results)
                
                # Verify DLEQ proofs
                if not self._verify_silent_payment_dleq_proofs():
                    if DEBUG:
                        print("SP preview: DLEQ proof verification failed")
                    return False
                
                # Compute output scripts (this updates outp.script)
                self._compute_silent_payment_output_scripts()
                
                if DEBUG:
                    print("Silent Payment outputs previewed successfully")
                
                return True
                
        except Exception as e:
            if DEBUG:
                print("SP preview failed: %s" % e)
            # Fallback to placeholder - not a fatal error
            return False


    def process_silent_payments_for_signing(self, sv, dis):
        """
        Complete silent payment processing during signing phase
        
        Orchestrates the full silent payment workflow:
        1. Compute and store ECDH shares
        2. Verify DLEQ proofs
        3. Finalize output scripts (if single-signer)
        
        Args:
            sv: SensitiveValues context (already open)
            dis: Display object for user feedback
            
        Returns:
            tuple: (ux_title: str, ux_message: str) for display to user
            
        Raises:
            FatalPSBTIssue: If any step fails
        """
        from exceptions import FatalPSBTIssue
        
        dis.fullscreen('Silent Payment...')
        
        # Extract scan keys from silent payment outputs
        scan_keys = self._get_silent_payment_scan_keys()
        
        if DEBUG:
            print("Found %d silent payment output(s) with %d unique scan key(s)" % 
                  (sum(1 for o in self.outputs if o.sp_v0_info), len(scan_keys)))
        
        # Compute ECDH shares for our inputs
        try:
            ecdh_results = self._compute_silent_payment_ecdh_shares(scan_keys, sv)
            
            if not ecdh_results:
                raise FatalPSBTIssue("Unable to compute ECDH shares for silent payment outputs")
            
            # Store the computed shares
            self._store_silent_payment_ecdh_shares(ecdh_results)
            
            if DEBUG:
                print("Computed ECDH shares for %d scan key(s)" % len(ecdh_results))
            
        except Exception as e:
            if DEBUG:
                print("Silent payment ECDH computation failed: %s" % e)
            raise FatalPSBTIssue("Silent payment ECDH computation failed: %s" % e)
        
        # Verify all DLEQ proofs (including from other signers if multi-party)
        dis.fullscreen('Verifying Proofs...')
        if not self._verify_silent_payment_dleq_proofs():
            raise FatalPSBTIssue("Silent payment DLEQ proof verification failed")
        
        # Determine if we should finalize outputs now or wait for other signers
        all_inputs_ours = self._check_all_inputs_owned()
        
        if all_inputs_ours:
            # Check if outputs already computed during preview
            already_computed = all(
                outp.script and len(outp.script) == 34 and outp.script[0] == 0x51
                for outp in self.outputs if outp.sp_v0_info
            )
            
            if not already_computed:
                # Single signer - finalize now
                dis.fullscreen('Computing Outputs...')
                try:
                    self.finalize_silent_payment_outputs()
                    if DEBUG:
                        print("Silent payment output scripts computed successfully")
                except Exception as e:
                    raise FatalPSBTIssue("Silent payment output script computation failed: %s" % e)
            else:
                if DEBUG:
                    print("Silent payment outputs already computed during preview")
            
            return ("Silent Payments", "Output addresses computed and finalized")
        else:
            # Multi-signer - partial signing only
            if DEBUG:
                print("Partial SP signing - ECDH shares added, waiting for other signers")
            return ("Silent Payments", 
                    "Partial signature added. Other signers must contribute before outputs can be finalized")


# -----------------------------------------------------------------------------
# Internal Functions
# -----------------------------------------------------------------------------


    def _check_all_inputs_owned(self):
        """
        Check if all Silent Payment inputs belong to this signer
        
        Returns:
            bool: True if single signer owns all SP inputs, False if multi-party
        """
        all_inputs_ours = True
        for inp in self.inputs:
            if inp.sp_idxs:
                # Check if this input belongs to a different signer
                if inp.taproot_subpaths:
                    for _, path_coords in inp.taproot_subpaths:
                        xfp_path = self.parse_xfp_path(path_coords)
                        xfp = xfp_path[0]
                        if xfp != self.my_xfp and xfp != 0:
                            all_inputs_ours = False
                            break
                elif inp.subpaths:
                    for _, path_coords in inp.subpaths:
                        xfp_path = self.parse_xfp_path(path_coords)
                        xfp = xfp_path[0]
                        if xfp != self.my_xfp and xfp != 0:
                            all_inputs_ours = False
                            break
            if not all_inputs_ours:
                break
        return all_inputs_ours


    def _compute_ecdh_shares_internal(self, scan_keys, sv):
        """
        Internal function to compute ECDH shares for silent payment outputs
        
        For each scan_key, computes: sum(privkey_i * scan_key) for all inputs
        we control and can sign.
        
        Args:
            scan_keys: List of scan public keys (33 bytes each)
            sv: SensitiveValues context (already open from sign_it)
        
        Returns:
            dict: Mapping of scan_key -> (ecdh_share_bytes, dleq_proof_bytes)
        
        Raises:
            FatalPSBTIssue: If unable to compute ECDH shares
        """
        # secp256k1 curve order
        SECP256K1_ORDER = ngu.secp256k1.curve_order_int()

        results = {}
        
        for scan_key in scan_keys:
            # Collect private keys from all our inputs
            # For silent payments, we need to combine all input private keys
            combined_privkey = 0
            
            for inp in self.inputs:
                if not inp.sp_idxs:
                    continue  # Not our input
                
                # Get the private key for this input
                # This requires access to the wallet's master key
                try:
                    # Get the derivation path for this input
                    if inp.taproot_subpaths:
                        # Taproot input
                        for key_coords, path_coords in inp.taproot_subpaths:
                            pubkey = self.get(key_coords)
                            xfp_path = self.parse_xfp_path(path_coords)
                            xfp = xfp_path[0]
                            
                            if xfp == self.my_xfp:
                                # Derive private key for this path
                                from utils import keypath_to_str
                                path_str = keypath_to_str(xfp_path, skip=1)
                                node = sv.derive_path(path_str, register=False)
                                privkey_bytes = node.privkey()
                                privkey_int = int.from_bytes(privkey_bytes, 'big')
                                combined_privkey = (combined_privkey + privkey_int) % SECP256K1_ORDER
                                break
                    elif inp.subpaths:

                        # Non-taproot input
                        for key_coords, path_coords in inp.subpaths:
                            pubkey = self.get(key_coords)
                            xfp_path = self.parse_xfp_path(path_coords)
                            xfp = xfp_path[0]
                            
                            if xfp == self.my_xfp:
                                # Derive private key for this path
                                from utils import keypath_to_str
                                path_str = keypath_to_str(xfp_path, skip=1)
                                node = sv.derive_path(path_str, register=False)
                                privkey_bytes = node.privkey()
                                privkey_int = int.from_bytes(privkey_bytes, 'big')
                                combined_privkey = (combined_privkey + privkey_int) % SECP256K1_ORDER
                                break

                except Exception as e:

                    # Unable to derive private key for this input
                    if DEBUG:
                        print("Warning: Unable to derive privkey for input: %s" % e)
                    continue
            
            if combined_privkey == 0:
                # No inputs we can sign
                continue
            
            # Compute ECDH share
            ecdh_share = compute_ecdh_share(combined_privkey, scan_key)
            
            # Generate DLEQ proof
            # Use hardware RNG for aux_rand
            aux_rand = bytearray(32)
            ckcc.rng_bytes(aux_rand)
            dleq_proof = generate_dleq_proof(combined_privkey, scan_key, bytes(aux_rand))
            
            results[scan_key] = (ecdh_share, dleq_proof)
        
        return results


    def _compute_silent_payment_ecdh_shares(self, scan_keys, sv):
        """
        Compute ECDH shares for silent payment outputs (without storing)
        
        This is a pure computation function that does not modify PSBT state.
        Use store_silent_payment_ecdh_shares() to persist results.
        
        Args:
            scan_keys: List of scan public keys (33 bytes each)
            sv: SensitiveValues context (already open from sign_it)
        
        Returns:
            dict: Mapping of scan_key -> (ecdh_share_bytes, dleq_proof_bytes)
        
        Raises:
            FatalPSBTIssue: If unable to compute ECDH shares
        """
        return self._compute_ecdh_shares_internal(scan_keys, sv)


    def _compute_combined_pubkey(self):
        """
        Compute combined public key from all inputs we control
        
        Returns:
            bytes: Combined public key (33 bytes compressed)
        
        Raises:
            FatalPSBTIssue: If no public keys found
        """
        pubkeys = []
        
        for inp in self.inputs:
            if not inp.sp_idxs:
                continue
            
            # Get public key from this input
            if inp.taproot_subpaths:
                for pk_coords, path_coords in inp.taproot_subpaths:
                    xfp_path = self.parse_xfp_path(path_coords)
                    if xfp_path[0] == self.my_xfp or xfp_path[0] == 0:
                        pubkeys.append(self.get(pk_coords))
                        break
            elif inp.subpaths:
                for pk_coords, path_coords in inp.subpaths:
                    xfp_path = self.parse_xfp_path(path_coords)
                    if xfp_path[0] == self.my_xfp or xfp_path[0] == 0:
                        pubkeys.append(self.get(pk_coords))
                        break
        
        if not pubkeys:
            raise FatalPSBTIssue("No public keys found for DLEQ verification")
        
        # Combine using helper
        return combine_pubkeys(pubkeys)


    def _compute_silent_payment_output_scripts(self):
        """
        Compute final output scripts for silent payment outputs
        
        Uses global ECDH shares if available, otherwise combines per-input shares.
        This should only be called after all ECDH shares have been computed
        and verified. It derives the final P2TR output scripts.
        
        Raises:
            FatalPSBTIssue: If ECDH shares are missing or output derivation fails
        """
        
        # Collect outpoints and public keys for input hash computation
        outpoints = []
        pubkeys = []
        
        for inp in self.inputs:
            if not inp.sp_idxs:
                continue  # Not eligible for silent payments
            
            # Get outpoint (txid, vout)
            if inp.previous_txid and inp.prevout_idx is not None:
                outpoints.append((self.get(inp.previous_txid), self.get(inp.prevout_idx)))
            else:
                raise FatalPSBTIssue("Missing outpoint information for silent payment input")
            
            # Get public key from this input
            if inp.taproot_subpaths:
                for pk_coords, path_coords in inp.taproot_subpaths:
                    xfp_path = self.parse_xfp_path(path_coords)
                    if xfp_path[0] == self.my_xfp or xfp_path[0] == 0:
                        pubkeys.append(self.get(pk_coords))
                        break
            elif inp.subpaths:
                for pk_coords, path_coords in inp.subpaths:
                    xfp_path = self.parse_xfp_path(path_coords)
                    if xfp_path[0] == self.my_xfp or xfp_path[0] == 0:
                        pubkeys.append(self.get(pk_coords))
                        break
        
        if not outpoints:
            raise FatalPSBTIssue("No eligible inputs found for silent payment output computation")
        
        if not pubkeys:
            raise FatalPSBTIssue("No public keys found for silent payment inputs")
        
        # Compute summed public key
        summed_pubkey = combine_pubkeys(pubkeys)
        
        # Compute input hash
        input_hash = compute_input_hash(outpoints, summed_pubkey)
        
        # Collect ECDH shares (global or per-input)
        ecdh_shares = {}  # scan_key -> combined_ecdh_share
        
        # Check for global ECDH shares first
        if self.sp_global_ecdh_shares:
            if DEBUG:
                print("Using GLOBAL ECDH shares for output computation")
            
            for key_coords, share_coords in self.sp_global_ecdh_shares:
                scan_key = self.get(key_coords)
                ecdh_share = self.get(share_coords)
                ecdh_shares[scan_key] = ecdh_share
        else:
            # Combine per-input shares
            if DEBUG:
                print("Combining PER-INPUT ECDH shares for output computation")
            
            for idx, inp in enumerate(self.inputs):
                if inp.sp_ecdh_shares:
                    for key_coords, share_coords in inp.sp_ecdh_shares:
                        scan_key = self.get(key_coords)
                        ecdh_share = self.get(share_coords)
                        
                        if scan_key not in ecdh_shares:
                            # First share for this scan key - store as bytes
                            ecdh_shares[scan_key] = ecdh_share
                        else:
                            # Combine with existing share using point addition
                            ecdh_shares[scan_key] = ngu.secp256k1.ec_pubkey_combine(
                                ecdh_shares[scan_key], ecdh_share)
        
        if not ecdh_shares:
            raise FatalPSBTIssue("No ECDH shares found for silent payment outputs")
        
        # Process each silent payment output
        sp_output_count = 0
        for out_idx, outp in enumerate(self.outputs):
            if not outp.sp_v0_info:
                continue
            
            # Extract scan_key and spend_key
            sp_info = self.get(outp.sp_v0_info)
            scan_key = sp_info[:33]
            spend_key = sp_info[33:66]
            
            # Get ECDH share for this scan key
            if scan_key not in ecdh_shares:
                raise FatalPSBTIssue("Missing ECDH share for output #%d" % out_idx)
            
            ecdh_share = ecdh_shares[scan_key]
            
            # Derive output public key with input hash
            # Use output index k = sp_output_count (index among silent payment outputs)
            output_pubkey = derive_silent_payment_output_pubkey(
                spend_key, ecdh_share, sp_output_count, input_hash=input_hash)
            
            # Generate P2TR script
            script_pubkey = pubkey_to_p2tr_script(output_pubkey)
            
            # Store the derived script directly
            # This will replace the placeholder script in the transaction output
            outp.script = script_pubkey
            
            sp_output_count += 1
        
        if DEBUG:
            print("Computed %d silent payment output scripts" % sp_output_count)


    def _combine_silent_payment_shares(self, other_psbt):
        """
        Combine ECDH shares from another partially-signed PSBT
        
        This implements the PSBT Combiner role for BIP-375.
        Each signer contributes per-input ECDH shares and DLEQ proofs.
        The combiner merges all shares before final output computation.
        
        Args:
            other_psbt: Another psbtObject with partial SP signatures
        
        Raises:
            FatalPSBTIssue: If PSBTs are incompatible
        """
        # Verify PSBTs are for the same transaction
        if self.txn != other_psbt.txn:
            raise FatalPSBTIssue("Cannot combine: different transactions")
        
        # Merge per-input ECDH shares
        for idx, inp in enumerate(self.inputs):
            other_inp = other_psbt.inputs[idx]
            
            if other_inp.sp_ecdh_shares:
                if inp.sp_ecdh_shares is None:
                    inp.sp_ecdh_shares = []
                
                for scan_key_coords, share_coords in other_inp.sp_ecdh_shares:
                    scan_key = other_psbt.get(scan_key_coords)
                    share = other_psbt.get(share_coords)
                    
                    # Check if we already have a share for this scan_key
                    has_share = False
                    if inp.sp_ecdh_shares:
                        for existing_key_coords, _ in inp.sp_ecdh_shares:
                            if self.get(existing_key_coords) == scan_key:
                                has_share = True
                                break
                    
                    if not has_share:
                        # Store as in-memory bytes (not coordinates)
                        inp.sp_ecdh_shares.append((scan_key, share))
            
            # Merge DLEQ proofs
            if other_inp.sp_dleq_proofs:
                if inp.sp_dleq_proofs is None:
                    inp.sp_dleq_proofs = []
                
                for scan_key_coords, proof_coords in other_inp.sp_dleq_proofs:
                    scan_key = other_psbt.get(scan_key_coords)
                    proof = other_psbt.get(proof_coords)
                    
                    has_proof = False
                    if inp.sp_dleq_proofs:
                        for existing_key_coords, _ in inp.sp_dleq_proofs:
                            if self.get(existing_key_coords) == scan_key:
                                has_proof = True
                                break
                    
                    if not has_proof:
                        inp.sp_dleq_proofs.append((scan_key, proof))
        
        if DEBUG:
            print("Combined Silent Payment shares from another signer")

    def _encode_silent_payment_address(self, scan_pubkey, spend_pubkey, hrp="sp", version=0):
        """
        Encode a Silent Payment address using bech32m
        
        Uses ngu.codecs.bip352_encode which implements BIP-352 encoding in C.
        
        Args:
            scan_pubkey: 33-byte compressed scan public key (bytes)
            spend_pubkey: 33-byte compressed spend public key (bytes)
            hrp: Human-readable part (default "sp" for mainnet, "tsp" for testnet)
            version: Version byte (0-31 per BIP-352)
                     v0-v30: backward compatible
                     v31: reserved for backward-incompatible changes
        
        Returns:
            str: bech32m-encoded Silent Payment address (117 chars for v0)
        """
        # Ensure we have bytes, not tuples
        if not isinstance(scan_pubkey, (bytes, bytearray)):
            scan_pubkey = self.get(scan_pubkey)
        if not isinstance(spend_pubkey, (bytes, bytearray)):
            spend_pubkey = self.get(spend_pubkey)

        # Use the C implementation for encoding with version support
        address = ngu.codecs.bip352_encode(hrp, scan_pubkey, spend_pubkey, version)
        
        return address


    def _get_silent_payment_scan_keys(self):
        """
        Extract unique scan keys from silent payment outputs
        
        Returns:
            list: List of unique scan_key bytes (33 bytes each)
        """
        scan_keys = set()
        for outp in self.outputs:
            if outp.sp_v0_info:
                # sp_v0_info contains: scan_key (33 bytes) + spend_key (33 bytes)
                # Extract first 33 bytes (scan_key)
                scan_key = self.get(outp.sp_v0_info)[:33]
                scan_keys.add(scan_key)
        
        return list(scan_keys)


    def _is_silent_payment_ready_to_finalize(self):
        """
        Check if all required ECDH shares are present for finalization
        
        Returns:
            bool: True if ready to compute final output scripts
        """
        if not self.has_silent_payment_outputs():
            return True  # No SP outputs
        
        # Get all scan keys from outputs
        scan_keys = self._get_silent_payment_scan_keys()
        
        # Check if we have shares for all scan keys
        for scan_key in scan_keys:
            has_share = False
            
            # Check global shares
            if self.sp_global_ecdh_shares:
                for key_coords, _ in self.sp_global_ecdh_shares:
                    if self.get(key_coords) == scan_key:
                        has_share = True
                        break
            
            # Check per-input shares
            if not has_share:
                for inp in self.inputs:
                    if inp.sp_ecdh_shares:
                        for key_coords, _ in inp.sp_ecdh_shares:
                            if self.get(key_coords) == scan_key:
                                has_share = True
                                break
                    if has_share:
                        break
            
            if not has_share:
                return False  # Missing share for this scan key
        
        # Verify all DLEQ proofs
        if not self._verify_silent_payment_dleq_proofs():
            return False
        
        return True


    def _store_silent_payment_ecdh_shares(self, ecdh_results):
        """
        Store ECDH shares and DLEQ proofs in PSBT fields
        
        Idempotent: will not duplicate shares if they already exist.
        
        Args:
            ecdh_results: dict from compute_silent_payment_ecdh_shares()
                         Mapping of scan_key -> (ecdh_share_bytes, dleq_proof_bytes)
        """
        if not ecdh_results:
            return
        
        # Determine if we own all inputs (single signer scenario)
        all_inputs_ours = self._check_all_inputs_owned()
        
        # Store results based on ownership
        for scan_key, (ecdh_share, dleq_proof) in ecdh_results.items():
            if all_inputs_ours:
                # Use GLOBAL fields (single signer owns all inputs)
                if self.sp_global_ecdh_shares is None:
                    self.sp_global_ecdh_shares = []
                if self.sp_global_dleq_proofs is None:
                    self.sp_global_dleq_proofs = []
                
                # Check if share already exists
                share_exists = False
                if self.sp_global_ecdh_shares:
                    for existing_key, _ in self.sp_global_ecdh_shares:
                        if existing_key == scan_key:
                            share_exists = True
                            break
                
                if not share_exists:
                    if DEBUG:
                        print("Storing GLOBAL SP fields (single signer)")
                    
                    self.sp_global_ecdh_shares.append((scan_key, ecdh_share))
                    self.sp_global_dleq_proofs.append((scan_key, dleq_proof))
            else:
                # Use PER-INPUT fields (multi-party signing)
                if DEBUG:
                    print("Storing PER-INPUT SP fields (multi-party)")
                
                for inp in self.inputs:
                    if inp.sp_idxs:
                        if inp.sp_ecdh_shares is None:
                            inp.sp_ecdh_shares = []
                        if inp.sp_dleq_proofs is None:
                            inp.sp_dleq_proofs = []
                        
                        # Check if share already exists for this input
                        share_exists = False
                        if inp.sp_ecdh_shares:
                            for existing_key, _ in inp.sp_ecdh_shares:
                                if existing_key == scan_key:
                                    share_exists = True
                                    break
                        
                        if not share_exists:
                            if DEBUG:
                                print("  Adding to input - scan_key:", b2a_hex(scan_key))
                            
                            inp.sp_ecdh_shares.append((scan_key, ecdh_share))
                            inp.sp_dleq_proofs.append((scan_key, dleq_proof))


    def _verify_silent_payment_dleq_proofs(self):
        """
        Verify all DLEQ proofs in the PSBT (global or per-input)
        
        Priority:
        1. Check global proofs first (if present)
        2. Fall back to per-input proofs
        
        Returns:
            bool: True if all proofs verify, False otherwise
        """
        # Check for global DLEQ proofs first
        if self.sp_global_dleq_proofs:
            if DEBUG:
                print("Verifying GLOBAL DLEQ proofs")
            
            # Compute combined public key for verification
            try:
                combined_pubkey = self._compute_combined_pubkey()
            except FatalPSBTIssue as e:
                if DEBUG:
                    print("Failed to compute combined pubkey:", e)
                return False
            
            # Verify each global proof
            for key_coords, proof_coords in self.sp_global_dleq_proofs:
                scan_key = self.get(key_coords)
                proof = self.get(proof_coords)
                
                # Find corresponding global ECDH share
                ecdh_share = None
                if self.sp_global_ecdh_shares:
                    for ecdh_key_coords, ecdh_share_coords in self.sp_global_ecdh_shares:
                        if self.get(ecdh_key_coords) == scan_key:
                            ecdh_share = self.get(ecdh_share_coords)
                            break
                
                if ecdh_share is None:
                    if DEBUG:
                        print("Missing ECDH share for global proof")
                    return False
                
                if DEBUG:
                    print("  Verifying global proof for scan_key:", b2a_hex(scan_key))
                
                if not verify_dleq_proof(combined_pubkey, scan_key, ecdh_share, proof):
                    if DEBUG:
                        print("  Global DLEQ proof verification FAILED")
                    return False
            
            return True
        
        # Fall back to per-input DLEQ proofs
        if DEBUG:
            print("Verifying PER-INPUT DLEQ proofs")
        
        # Check per-input DLEQ proofs
        # Invariant: If a DLEQ proof exists, the corresponding ECDH share MUST exist
        for idx, inp in enumerate(self.inputs):
            if not inp.sp_dleq_proofs:
                # No proofs for this input - skip (valid for unsigned inputs)
                continue
            
            # Input has DLEQ proofs - verify each one
            for key_coords, proof_coords in inp.sp_dleq_proofs:
                scan_key = self.get(key_coords)
                proof = self.get(proof_coords)
                
                # Find the matching ECDH share for this scan key
                ecdh_share = None
                if inp.sp_ecdh_shares:
                    for ecdh_share_scankey, share in inp.sp_ecdh_shares:
                        if ecdh_share_scankey == scan_key:
                            ecdh_share = share
                            break
                
                # CRITICAL: DLEQ proof exists but no matching ECDH share = FAIL
                if ecdh_share is None:
                    if DEBUG:
                        print("FATAL: DLEQ proof found but no matching ECDH share")
                        print("  Input:", idx)
                        print("  Scan key:", b2a_hex(scan_key))
                    return False
                
                # Get the public key for this input to verify the proof
                pubkey = None
                if inp.taproot_subpaths:
                    for pk_coords, _ in inp.taproot_subpaths:
                        pubkey = self.get(pk_coords)
                        break
                elif inp.subpaths:
                    for pk_coords, _ in inp.subpaths:
                        pubkey = self.get(pk_coords)
                        break
                
                if pubkey is None:
                    if DEBUG:
                        print("FATAL: No pubkey found for DLEQ verification")
                        print("  Input:", idx)
                    return False
                
                # Verify the DLEQ proof
                if not verify_dleq_proof(pubkey, scan_key, ecdh_share, proof):
                    if DEBUG:
                        print("FATAL: DLEQ proof verification failed")
                        print("  Input:", idx)
                        print("  Scan key:", b2a_hex(scan_key))
                    return False

        return True