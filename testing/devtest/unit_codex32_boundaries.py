# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
# Additional coverage; the published vectors remain in unit_codex32.py.

# Keep imports in function scope for the simulator EXEC harness.
def run():
    import ngu
    from codex32 import CHARSET, SECRET, Share, generate_share
    from stash import SecretStash
    from utils import deserialize_secret

    def rejected(func, args, case, message=None):
        try:
            func(*args)
        except AssertionError as exc:
            assert message is None or message in str(exc), (case, str(exc))
        else:
            assert False, ('accepted invalid input', case)

    def fields(share):
        # Compare all encoded data, including padding, without recomputing checksums.
        return share.hrp, share.uid, share.index, share.threshold, share.payload

    def storage_roundtrip(share, case):
        if not share.is_secret_share():
            rejected(SecretStash.encode, (None, None, None, share), case)
        else:
            encoded = SecretStash.encode(codex32=share)
            assert len(encoded) == 72 and encoded[65:] == bytes(7), case
            restored = deserialize_secret(SecretStash.storage_serialize(encoded))
            assert restored == encoded, case
            mode, raw, node = SecretStash.decode(restored)
            try:
                assert raw == share.to_seed_and_pad()[0], case
                assert mode == {'ms': 'master', 'cw': 'words', 'cx': 'xprv'}[share.hrp], case
            finally:
                node.blank()
        return Share.parse(share.to_string())

    FORMATS = (('ms', 16), ('ms', 32), ('ms', 64), ('cx', 64),
               ('cw', 16), ('cw', 24), ('cw', 32))
    INDICES = 'acdefghjk'

    for hrp, size in FORMATS:
        label = '%s1 %d-bit' % (hrp.upper(), size * 8)
        print('Codex32 %s: testing thresholds, padding and storage...' % label)
        seed = bytes(range(size))
        pad_count = 1 << ((-size * 8) % 5)

        # Recover every threshold from distinct subsets and reversed order.
        for threshold in range(2, 10):
            case = (hrp, size, 'threshold', threshold)
            secret = Share.from_seed(seed, hrp, 'test', SECRET, threshold, pad_count - 1)
            shares = [Share.from_seed(ngu.hash.sha512(bytes([i])).digest()[:size],
                                      hrp, 'test', INDICES[i], threshold, i % pad_count)
                      for i in range(threshold - 1)]
            basis = [secret] + shares
            for index in INDICES[threshold - 1:]:
                shares.append(generate_share(basis, index))
            shares = [storage_roundtrip(share, case) for share in shares]
            for subset in (shares[:threshold], shares[-threshold:],
                           list(reversed(shares[:threshold]))):
                recovered = generate_share(subset, SECRET)
                assert fields(recovered) == fields(secret), (case, [s.index for s in subset])

            # Extra points must be rejected even if they fit the original polynomial.
            subset = shares[:threshold]
            extra = generate_share(subset, 'm')
            bad_payload = CHARSET[CHARSET.index(extra.payload[0]) ^ 1] + extra.payload[1:]
            inconsistent = Share(hrp, 'test', bad_payload, 'm', threshold)
            inconsistent = Share.parse(inconsistent.to_string())  # Valid checksum.
            for target in (SECRET, 'n'):
                for inputs in (subset[:-1], subset + [extra], subset + [inconsistent]):
                    rejected(generate_share, (inputs, target), (case, target),
                             'need exactly %d shares' % threshold)

        # Exhaust all padding values for secrets and non-secret shares, including recovery.
        for pad in range(pad_count):
            case = (hrp, size, 'padding', pad)
            secret = Share.from_seed(seed, hrp, 'cash', SECRET, 2, pad)
            first = Share.from_seed(bytes(reversed(seed)), hrp, 'cash', 'a', 2, pad)
            for share, expected_seed in ((secret, seed), (first, bytes(reversed(seed)))):
                assert share.to_seed_and_pad() == (expected_seed, pad), case
                text = share.to_string()
                for value in (text, text.lower()):
                    assert fields(Share.parse(value)) == fields(share), case
                storage_roundtrip(share, case)
            second = storage_roundtrip(generate_share([secret, first], 'c'), case)
            assert fields(generate_share([second, first], SECRET)) == fields(secret), case

        # Cover every index and identifier character without multiplying the entire matrix.
        for pos, index in enumerate(CHARSET):
            case = (hrp, size, 'index', index)
            share = Share.from_seed(seed, hrp, 'q' + index + 'l7', index,
                                    2 + pos % 8, pad_count - 1)
            storage_roundtrip(share, case)

        for pad in (-1, pad_count):
            rejected(Share.from_seed, (seed, hrp, 'test', SECRET, 2, pad),
                     (hrp, size, 'invalid padding', pad))

        print('Codex32 %s: OK' % label)

    print('Codex32 thresholds, padding, indices and storage rejection: OK')

    # These mismatches must be rejected by interpolation itself, independently of the UI.
    first = Share.from_seed(bytes(range(64)), 'ms', 'test', 'a', 2, 0)
    for second, message in (
            (Share.from_seed(bytes(range(64)), 'cx', 'test', 'c', 2, 0), 'hrp not same'),
            (Share.from_seed(bytes(range(32)), 'ms', 'test', 'c', 2, 0), 'length not same')):
        rejected(generate_share, ([first, second], SECRET), message, message)
    rejected(generate_share, ([], SECRET), 'empty recovery', 'no shares')

    # CW1 preserves the legacy words representation and its passphrase semantics.
    for size in (16, 24, 32):
        entropy = bytes(range(size))
        share = Share.from_seed(entropy, 'cw', 'test', SECRET, 2, 1)
        encoded = SecretStash.encode(codex32=share)
        legacy = SecretStash.encode(seed_phrase=entropy)
        assert encoded == legacy
        assert SecretStash.is_words(encoded) == size * 3 // 4
        for pw in ('', 'TREZOR'):
            mode, raw, node = SecretStash.decode(encoded, pw)
            _, _, expected = SecretStash.decode(legacy, pw)
            try:
                assert mode == 'words' and raw == entropy
                assert node.chain_code() == expected.chain_code()
                assert node.privkey() == expected.privkey()
            finally:
                node.blank()
                expected.blank()

    for size in (20, 28, 64):
        bad = Share.from_seed(bytes(range(size)), 'cw', 'test', SECRET, 2)
        rejected(Share.parse, (bad.to_string(),), ('cw', size), 'cw codex32 length')
        rejected(SecretStash.encode, (None, None, None, bad), ('cw storage', size))
    first = Share.from_seed(bytes(range(16)), 'cw', 'test', 'a', 2, 0)
    second = Share.from_seed(bytes(range(16)), 'ms', 'test', 'c', 2, 0)
    rejected(generate_share, ([first, second], SECRET), 'cw/ms mix', 'hrp not same')

    print('Codex32 recovery rejection and legacy storage: OK')


run()

# EOF
