# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test_paper_dice_warning.py - regression test: PaperWalletMaker.use_dice()
# must show DICE_ONLY_WARNING before rolling dice.
#
# Covers: commit 71763b2c ("Warn before dice-only seed generation") added the
# warning to new_from_dice() and make_new_codex32_wallet(), but the paper
# wallet "Use Dice" flow (Advanced/Tools -> Paper Wallets -> Use Dice) went
# straight into add_dice_rolls() with no warning, even though the hash shown
# while rolling is the secret key material. Reported by iblitzc0de.
#
# This test is self-contained: it extracts the REAL use_dice() method source
# from shared/paper.py via AST (so it always exercises the shipped code rather
# than a copy of it) and shims the MicroPython/UX layer. Run with plain
# CPython pytest:  pytest testing/test_paper_dice_warning.py
#
import ast
import asyncio
import os

SHARED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared")


def _real_dice_only_warning():
    # Verbatim warning text from the shipped firmware (shared/seed.py).
    src = open(os.path.join(SHARED, "seed.py")).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "DICE_ONLY_WARNING":
                    return ast.literal_eval(node.value)
    raise RuntimeError("DICE_ONLY_WARNING not found in shared/seed.py")


def _real_use_dice():
    # Verbatim method from the shipped firmware (shared/paper.py).
    src = open(os.path.join(SHARED, "paper.py")).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "PaperWalletMaker":
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "use_dice":
                    seg = ast.get_source_segment(src, item)
                    assert seg is not None, "could not extract use_dice"
                    ns = {}
                    exec(compile(ast.parse(seg), "<paper.py>", "exec"), ns)
                    return ns["use_dice"]
    raise RuntimeError("use_dice not found in shared/paper.py")


DICE_ONLY_WARNING = _real_dice_only_warning()
_use_dice = _real_use_dice()


class _Harness:
    # Shims for the MicroPython/UX layer use_dice() touches.
    def __init__(self, story_result="ok"):
        self.calls = []
        self.story_result = story_result
        self.doit_called_with = None

    # -- shims injected into the extracted function's namespace --
    def imported(self, name):
        assert name == "seed", name
        harness = self

        class _Ctx:
            def __enter__(self):
                return harness._fake_seed()

            def __exit__(self, *a):
                return False

        return _Ctx()

    def _fake_seed(self):
        harness = self

        class _Seed:
            DICE_ONLY_WARNING = DICE_ONLY_WARNING

            async def add_dice_rolls(self, count, seed, *a, **k):
                harness.calls.append("add_dice_rolls")
                return 99, b"\x01" * 32

        return _Seed()

    async def ux_show_story(self, story, title=None):
        self.calls.append(("story", title, story))
        return self.story_result

    # -- fake PaperWalletMaker instance --
    async def doit(self, have_key=None):
        self.calls.append("doit")
        self.doit_called_with = have_key
        return "wallet-made"

    def run(self):
        ns = {
            "imported": self.imported,
            "ux_show_story": self.ux_show_story,
            "OK": "OK",
            "X": "X",
            "SECP256K1_ORDER": b"\xff" * 32,
        }
        return asyncio.run(_call(_use_dice, self, ns))


async def _call(fn, self, ns):
    # Bind shims as globals of the extracted function, then invoke as method.
    fn.__globals__.update(ns)
    return await fn(self)


def _run(story_result):
    h = _Harness(story_result=story_result)
    h.run()
    return h


def test_warning_shown_before_any_rolls():
    h = _run("ok")
    kinds = [c if isinstance(c, str) else c[0] for c in h.calls]
    assert "story" in kinds and "add_dice_rolls" in kinds
    # warning must come before the first roll is accepted
    assert kinds.index("story") < kinds.index("add_dice_rolls")
    title, story = h.calls[0][1], h.calls[0][2]
    assert title == "WARNING"
    assert story.startswith(DICE_ONLY_WARNING), "warning text drifted from seed.py"
    assert "SECRET" in story


def test_exit_at_warning_aborts_without_rolling():
    h = _run("x")
    kinds = [c if isinstance(c, str) else c[0] for c in h.calls]
    assert kinds == ["story"], f"expected early return, got: {kinds}"
    assert h.doit_called_with is None


def test_continue_proceeds_to_wallet():
    h = _run("ok")
    kinds = [c if isinstance(c, str) else c[0] for c in h.calls]
    assert kinds == ["story", "add_dice_rolls", "doit"]
    assert h.doit_called_with == b"\x01" * 32


if __name__ == "__main__":
    test_warning_shown_before_any_rolls()
    test_exit_at_warning_aborts_without_rolling()
    test_continue_proceeds_to_wallet()
    print("all paper dice-warning tests pass")
