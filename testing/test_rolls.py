import sys
sys.path.append("..")
from docs.rolls import entropy_to_mnemonic24
from docs.rolls12 import entropy_to_mnemonic12


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
