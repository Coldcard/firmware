# Usage: python3 rolls_codex32.py --bits 128 < rolls.txt
# Requires Python 3 and nothing else. Keep rolls and output secret.
# Public domain.

import argparse
import sys
from hashlib import sha256

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def encode_seed(seed, uid):
    # Encode bytes as five-bit symbols with zero padding.
    groups = (len(seed) * 8 + 4) // 5
    value = int.from_bytes(seed, 'big') << (groups * 5 - len(seed) * 8)
    payload = ''.join(CHARSET[(value >> (5 * i)) & 31]
                      for i in range(groups - 1, -1, -1))
    body = '0' + uid + 's' + payload

    # Codex32 short checksum, sufficient for 128- and 256-bit secrets.
    hrp = 'ms'
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    values += [CHARSET.index(c) for c in body] + [0] * 13
    generators = (0x19dc500ce73fde210, 0x1bfae00def77fe529,
                  0x1fbd920fffe7bee52, 0x1739640bdeee3fdad, 0x07729a039cfc75f5a)
    residue = 1
    for value in values:
        top = residue >> 60
        residue = ((residue & 0x0fffffffffffffff) << 5) ^ value
        for i, generator in enumerate(generators):
            if (top >> i) & 1:
                residue ^= generator
    residue ^= 0x10ce0795c2fd1e62a
    checksum = ''.join(CHARSET[(residue >> (5 * i)) & 31] for i in range(12, -1, -1))
    return (hrp + '1' + body + checksum).upper()


def main():
    parser = argparse.ArgumentParser(description='Verify a dice-only Codex32 secret.')
    parser.add_argument('--bits', type=int, choices=(128, 256), required=True)
    parser.add_argument('--id', default='seed',
                        help='four-character ID (default: SEED; override for older backups)')
    args = parser.parse_args()
    uid = args.id.lower()
    if len(uid) != 4 or any(c not in CHARSET for c in uid):
        parser.error('ID must contain four Codex32 characters')

    rolls = ''.join(sys.stdin.read().split())
    if not rolls or any(c not in '123456' for c in rolls):
        parser.error('rolls must contain only digits 1-6 (whitespace is ignored)')
    minimum = 50 if args.bits == 128 else 99
    if len(rolls) < minimum:
        parser.error('at least %d rolls required' % minimum)
    if any(rolls.count(c) / len(rolls) > 0.30 for c in '123456'):
        parser.error('some numbers occurred more than 30% of the time')

    digest = sha256(rolls.encode('ascii')).digest()
    print(digest.hex())
    print()
    print(encode_seed(digest[:args.bits // 8], uid))


if __name__ == '__main__':
    main()
