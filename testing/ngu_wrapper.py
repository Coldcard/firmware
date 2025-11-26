"""
NGU Wrapper for Testing

This module provides access to the ngu C library by using the compiled
coldcard-mpy MicroPython binary. It allows pytest to call ngu functions
that are built into the simulator.
"""

import subprocess
import sys
import os
from pathlib import Path

# Find the coldcard-mpy binary
REPO_ROOT = Path(__file__).parent.parent
COLDCARD_MPY = REPO_ROOT / "unix" / "coldcard-mpy"

if not COLDCARD_MPY.exists():
    raise FileNotFoundError(
        f"coldcard-mpy not found at {COLDCARD_MPY}. "
        f"Build it first: cd unix && make -f Makefile"
    )


def _exec_mpy(code):
    """Execute Python code in coldcard-mpy and return the output"""
    try:
        result = subprocess.run(
            [str(COLDCARD_MPY), "-c", code],
            capture_output=True,
            text=False,  # Keep as bytes
            timeout=5
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"MicroPython execution failed:\n{result.stderr.decode('utf-8', errors='replace')}"
            )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError("MicroPython execution timed out")


class NGU_Secp256k1:
    """Wrapper for ngu.secp256k1 module using coldcard-mpy"""

    @staticmethod
    def pubkey(pubkey_bytes):
        """
        Validate a public key

        Args:
            pubkey_bytes: 33-byte compressed public key

        Returns:
            The pubkey_bytes if valid

        Raises:
            ValueError if invalid
        """
        if not isinstance(pubkey_bytes, bytes):
            raise TypeError("pubkey_bytes must be bytes")

        code = f"""
import ngu
import sys
from ubinascii import unhexlify, hexlify
pubkey_hex = {pubkey_bytes.hex()!r}
pubkey_bytes = unhexlify(pubkey_hex)
try:
    # ngu.secp256k1.pubkey() validates and returns a pubkey object
    pubkey_obj = ngu.secp256k1.pubkey(pubkey_bytes)
    # Serialize it back to bytes
    result = pubkey_obj.to_bytes()
    print(hexlify(result).decode())
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"""
        result_hex = _exec_mpy(code).decode().strip()
        return bytes.fromhex(result_hex)

    @staticmethod
    def ec_pubkey_tweak_mul(pubkey_bytes, scalar_bytes):
        """
        Multiply a public key by a scalar (pubkey * scalar)

        Args:
            pubkey_bytes: 33-byte compressed public key
            scalar_bytes: 32-byte scalar (big-endian integer)

        Returns:
            33-byte compressed public key result
        """
        if not isinstance(pubkey_bytes, bytes) or not isinstance(scalar_bytes, bytes):
            raise TypeError("Arguments must be bytes")

        code = f"""
import ngu
import sys
from ubinascii import unhexlify, hexlify
pubkey_hex = {pubkey_bytes.hex()!r}
scalar_hex = {scalar_bytes.hex()!r}
pubkey_bytes = unhexlify(pubkey_hex)
scalar_bytes = unhexlify(scalar_hex)
try:
    result = ngu.secp256k1.ec_pubkey_tweak_mul(pubkey_bytes, scalar_bytes)
    print(hexlify(result).decode())
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"""
        result_hex = _exec_mpy(code).decode().strip()
        return bytes.fromhex(result_hex)

    @staticmethod
    def ec_pubkey_combine(*pubkey_list):
        """
        Add multiple public keys together

        Args:
            *pubkey_list: Variable number of 33-byte compressed public keys

        Returns:
            33-byte compressed public key (sum of all inputs)
        """
        if len(pubkey_list) < 2:
            raise ValueError("Need at least 2 pubkeys to combine")

        pubkey_hexes = [pk.hex() for pk in pubkey_list]

        code = f"""
import ngu
import sys
from ubinascii import unhexlify, hexlify
pubkey_hexes = {pubkey_hexes!r}
pubkeys = [unhexlify(h) for h in pubkey_hexes]
try:
    result = ngu.secp256k1.ec_pubkey_combine(*pubkeys)
    print(hexlify(result).decode())
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"""
        result_hex = _exec_mpy(code).decode().strip()
        return bytes.fromhex(result_hex)

    @staticmethod
    def curve_order_int():
        """
        Return the curve order as an integer

        Args:
            None

        Returns:
            Curve order as an integer
        """

        code = f"""
import ngu
import sys
try:
    result = ngu.secp256k1.curve_order_int()
    print(result)
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"""
        result = _exec_mpy(code).decode().strip()
        return int(result)

    @staticmethod
    def generator():
        """
        Return the generator point as bytes

        Args:
            None

        Returns:
            Generator point as bytes
        """

        code = f"""
import ngu
import sys
from ubinascii import hexlify
try:
    result = ngu.secp256k1.generator()
    print(hexlify(result).decode())
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"""
        result_hex = _exec_mpy(code).decode().strip()
        return bytes.fromhex(result_hex)


class NGU_Hash:
    """Wrapper for ngu.hash module using coldcard-mpy"""
    
    @staticmethod
    def sha256t(tag_hash, msg, final):
        """
        Compute tagged SHA256 hash
        
        Args:
            tag_hash: Precomputed SHA256(tag) (32 bytes)
            msg: Message to hash (bytes)
            final: If True, return final hash; if False, return hasher object
        
        Returns:
            32-byte hash digest
        """
        if not isinstance(tag_hash, bytes) or len(tag_hash) != 32:
            raise ValueError("tag_hash must be 32 bytes")
        if not isinstance(msg, bytes):
            raise TypeError("msg must be bytes")
        if not final:
            raise NotImplementedError("Non-final hash not supported in wrapper")
        
        code = f"""
import ngu
from ubinascii import unhexlify, hexlify
tag_hash_hex = {tag_hash.hex()!r}
msg_hex = {msg.hex()!r}
tag_hash = unhexlify(tag_hash_hex)
msg = unhexlify(msg_hex)
try:
    result = ngu.hash.sha256t(tag_hash, msg, True)
    print(hexlify(result).decode())
except Exception as e:
    import sys
    sys.stderr.write(str(e))
    sys.exit(1)
"""
        result_hex = _exec_mpy(code).decode().strip()
        return bytes.fromhex(result_hex)


class NGU:
    """Mock ngu module with secp256k1 and hash submodules"""
    secp256k1 = NGU_Secp256k1()
    hash = NGU_Hash()


# Singleton instance
ngu = NGU()


# Example usage / self-test
if __name__ == "__main__":
    # Test ec_pubkey_tweak_mul
    from binascii import hexlify, unhexlify

    # Example: multiply generator point by a scalar
    G = unhexlify('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    scalar = b'\x00' * 31 + b'\x02'  # scalar = 2

    result = ngu.secp256k1.ec_pubkey_tweak_mul(G, scalar)
    print(f"G * 2 = {hexlify(result).decode()}")

    # Test validation
    try:
        ngu.secp256k1.pubkey(G)
        print("Pubkey validation: OK")
    except Exception as e:
        print(f"Pubkey validation failed: {e}")

    # Test combine
    result2 = ngu.secp256k1.ec_pubkey_combine(G, G)
    print(f"G + G = {hexlify(result2).decode()}")

    print("\nAll tests passed!")
