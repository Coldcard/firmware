import sys
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path
import pytest
sys.path.append("..")
from docs.rolls import entropy_to_mnemonic24, wl as rolls_wl
from docs.rolls12 import entropy_to_mnemonic12
from docs.verify_seed_mix import derive_seed, entropy_to_mnemonic, mnemonic24_to_entropy, wl as trng_wl
from docs.verify_seed_mix import encode_codex32
from docs.rolls_codex32 import encode_seed
from shared.codex32 import Share


bip39_vectors_12 = [
    (
        "c0ba5a8e914111210f2bd131f3d5e08d",
        "scheme spot photo card baby mountain device kick cradle pact join borrow",
    ),
    (
        "23db8160a31d3e0dca3688ed941adbf3",
        "cat swing flag economy stadium alone churn speed unique patch report train",
    ),
    (
        "f30f8c1da665478f49b001d94c5fc452",
        "vessel ladder alter error federal sibling chat ability sun glass valve picture",
    ),
    (
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
    ),
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    ),
    (
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ),
    (
        "bdfd931e398288992f60945db9e4e28a",
        "sadness uncle shy indoor chuckle erode rural barely frozen song december bicycle"
    ),
    (
        "96d646b36079d8c1197da69188b54388",
        "nothing rate proud science outside gauge grass regular muscle east extend axis"
    ),
]

bip39_vectors_24 = [
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
    ),
    (
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    ),
    (
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
    ),
    (
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
    ),
    (
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
    ),
    (
        "551bf03d054209b3d512dc4090a5067ae4bd41e487d9f14e5f709551d23564fe",
        "fence test aunt appear calm supreme february fortune dog lunch dose volume envelope path must will vanish indicate switch click brush boy negative skate"
    ),
    (
        "2debf1019b6e9f94c23236c1f481491cfdd684ad2ababa759025273c508fa83f",
        "combine garbage document cycle try skill angle egg sea piano false delay talent drastic regret firm risk prosper announce example shallow elephant path toddler"
    ),
    (
        "690a5584effb0b696ed901454cf88ce5aaa0785b5e00c1e859a10f4d0e0e06f7",
        "harbor famous gentle that radar regret rocket cage earn guitar case slender present destroy hope scale sea drift hair burden special alpha bridge valid"
    ),
]


def test_entropy_to_mnemonic12():
    for entropy, target_mnemonic in bip39_vectors_12:
        entropy_bytes = bytes.fromhex(entropy)
        assert " ".join(entropy_to_mnemonic12(entropy_bytes)) == target_mnemonic


def test_entropy_to_mnemonic24():
    for entropy, target_mnemonic in bip39_vectors_24:
        entropy_bytes = bytes.fromhex(entropy)
        assert " ".join(entropy_to_mnemonic24(entropy_bytes)) == target_mnemonic


def test_trng_words_report_unknown_word():
    words = bip39_vectors_24[0][1].replace('art', 'notaword')
    with pytest.raises(ValueError, match='unknown BIP39 word: notaword'):
        mnemonic24_to_entropy(words)


@pytest.mark.parametrize('nwords, expected', [
    (12, '67c8b6d836d47f88dfb88a1bb5a534cf'),
    (24, '67c8b6d836d47f88dfb88a1bb5a534cf28b437cd345e8c7fa59f1982f9248da5'),
])
def test_trng_dice_mix(nwords, expected):
    assert trng_wl == rolls_wl
    base_words = bip39_vectors_24[0][1]
    base_seed = mnemonic24_to_entropy(base_words)
    rolls = ('123456' * 8) + '12'

    seed = derive_seed(base_seed, rolls, 'd', nwords)

    assert seed.hex() == expected
    convert = entropy_to_mnemonic12 if nwords == 12 else entropy_to_mnemonic24
    assert entropy_to_mnemonic(seed) == convert(seed)


@pytest.mark.parametrize('nwords, expected', [
    (12, '8216d06056e31315bec14171d1f09345'),
    (24, '8216d06056e31315bec14171d1f09345eef5cbba16fdd3498354951dd3356dab'),
])
def test_trng_coin_mix(nwords, expected):
    base_words = bip39_vectors_24[0][1]
    base_seed = mnemonic24_to_entropy(base_words)
    flips = '01' * 64

    seed = derive_seed(base_seed, flips, 'c', nwords)

    assert seed.hex() == expected
    convert = entropy_to_mnemonic12 if nwords == 12 else entropy_to_mnemonic24
    assert entropy_to_mnemonic(seed) == convert(seed)


@pytest.mark.parametrize('encode', [encode_seed, encode_codex32])
@pytest.mark.parametrize('seed, uid, expected', [
    (bytes(16), 'test', 'MS10TESTSQQQQQQQQQQQQQQQQQQQQQQQQQQS75SVV7JAL8P5'),
    (bytes.fromhex('ffeeddccbbaa99887766554433221100' * 2), 'leet',
     'MS10LEETSLLHDMN9M42VCSAMX24ZRXGS3QRL7AHWVHW4FNZRHVE25GVEZZYQQTUM9PGV99YCMA'),
])
def test_codex32_encoders(encode, seed, uid, expected):
    assert encode(seed, uid) == expected


@pytest.fixture
def run_rolls_script(tmp_path):
    def run(name, args, data):
        script = tmp_path / name
        shutil.copyfile(Path(__file__).resolve().parents[1] / 'docs' / name, script)
        return subprocess.run([sys.executable, '-I', str(script), *args], input=data,
                              text=True, capture_output=True, cwd=tmp_path)
    return run


@pytest.mark.parametrize('codex32', [None, 'seed', 'test'])
@pytest.mark.parametrize('bits', [128, 256])
@pytest.mark.parametrize('method, tmp, expected', [
    ('d', False, '67c8b6d836d47f88dfb88a1bb5a534cf28b437cd345e8c7fa59f1982f9248da5'),
    ('d', True, 'c890c265e37b1da69636a6ed93bcfa2734232bcdcfd95908d7c1623f46af17cd'),
    ('c', False, '8216d06056e31315bec14171d1f09345eef5cbba16fdd3498354951dd3356dab'),
    ('c', True, '11e2749d5953a01b6d293fe3b3023fa2ab13426063f60e2529ebf195ad47b800'),
])
def test_seed_mix_script(run_rolls_script, codex32, bits, method, tmp, expected):
    args = ([] if codex32 is None else ['--codex32'] if codex32 == 'seed'
            else ['--codex32', 'TeSt']) + (['--tmp'] if tmp else [])
    symbols = '123456' * 8 + '12' if method == 'd' else '01' * 64
    size = bits if codex32 else (12 if bits == 128 else 24)
    data = '\n'.join([bip39_vectors_24[0][1], method, ' '.join(symbols), str(size)]) + '\n'
    result = run_rolls_script('verify_seed_mix.py', args, data)
    assert result.returncode == 0, result.stderr
    seed = bytes.fromhex(expected)[:bits // 8]
    assert '\n' + seed.hex() + '\n' in result.stdout
    if codex32:
        share = Share.parse(result.stdout.splitlines()[-1])
        assert (share.hrp, share.uid, share.index, share.threshold) == ('ms', codex32, 's', 0)
        assert share.to_seed_and_pad() == (seed, 0)
    else:
        convert = entropy_to_mnemonic12 if bits == 128 else entropy_to_mnemonic24
        expected_words = '\n'.join('%4d: %s' % item for item in enumerate(convert(seed), 1))
        assert result.stdout.endswith(expected_words + '\n')


@pytest.mark.parametrize('bits, minimum', [(128, 50), (256, 99)])
@pytest.mark.parametrize('uid', ['seed', 'test'])
def test_codex32_dice_script(run_rolls_script, bits, minimum, uid):
    args = ['--bits', str(bits)] + (['--id', 'TeSt'] if uid == 'test' else [])
    rolls = ('123456' * 17)[:minimum]
    result = run_rolls_script('rolls_codex32.py', args, ' \n' + '\t '.join(rolls) + '\n')
    assert result.returncode == 0, result.stderr
    digest = sha256(rolls.encode()).digest()
    assert result.stdout.splitlines()[0] == digest.hex()
    share = Share.parse(result.stdout.splitlines()[-1])
    assert (share.hrp, share.uid, share.index, share.threshold) == ('ms', uid, 's', 0)
    assert share.to_seed_and_pad() == (digest[:bits // 8], 0)

    for invalid, error in [
        ('', 'only digits 1-6'),
        (rolls + '0', 'only digits 1-6'),
        (rolls[:-1], 'at least %d rolls required' % minimum),
        ('1' * minimum, 'more than 30%'),
    ]:
        result = run_rolls_script('rolls_codex32.py', args, invalid)
        assert result.returncode == 2
        assert error in result.stderr
        assert not result.stdout


@pytest.mark.parametrize('script, args', [
    ('rolls_codex32.py', ['--bits', '128', '--id', 'tesb']),
    ('verify_seed_mix.py', ['--codex32', 'tesb']),
])
def test_codex32_scripts_invalid_id(run_rolls_script, script, args):
    result = run_rolls_script(script, args, '')
    assert result.returncode == 2
    assert 'ID must contain four Codex32 characters' in result.stderr
    assert not result.stdout
