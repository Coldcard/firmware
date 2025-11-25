

# MicroPython compatibility shims for testing
# This module provides standard Python equivalents for MicroPython-specific modules

import sys
import hashlib
import struct
import secrets

# Shim uhashlib -> hashlib
sys.modules['uhashlib'] = hashlib

# Shim ustruct -> struct
sys.modules['ustruct'] = struct

# Shim ubinascii -> binascii
import binascii
sys.modules['ubinascii'] = binascii

# Shim uos -> os
import os
sys.modules['uos'] = os

# Shim utime -> time
import time
sys.modules['utime'] = time

# Mock ckcc module for random number generation
class MockCKCC:
    """Mock Coldcard module for testing"""

    @staticmethod
    def rng(nbytes):
        """Generate random bytes using secrets module"""
        return secrets.token_bytes(nbytes)
    
    @staticmethod
    def rng_bytes(buf):
        """Fill buffer with random bytes (in-place)"""
        random_bytes = secrets.token_bytes(len(buf))
        for i in range(len(buf)):
            buf[i] = random_bytes[i]

    @staticmethod
    def is_simulator():
        return True

sys.modules['ckcc'] = MockCKCC()

# Add randbelow to random module for compatibility
# (Python 3's random module doesn't have randbelow, it's in secrets)
import random
if not hasattr(random, 'randbelow'):
    random.randbelow = secrets.randbelow
