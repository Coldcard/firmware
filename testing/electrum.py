# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Lightweight pytest wrapper around the `electrum` CLI in --regtest --offline mode.
# No backend (electrs/ElectrumX) needed: UTXOs are fed via `addtransaction`,
# with raw tx hex coming from the `bitcoind` fixture. Targets Electrum 4.7+

import os, time, shutil, pytest, tempfile, subprocess


class Electrum:
    def __init__(self, path):
        self.electrum_path = path
        self.datadir = tempfile.mkdtemp(prefix="electrum-test-")
        self.daemon_started = False

    def _cli(self, *args, offline=False):
        # `--offline` is required for commands run *before* the daemon starts
        # (setconfig, daemon -d) and rejected for commands that talk *to* the
        # running daemon (restore, load_wallet, addtransaction, payto).
        cmd = [self.electrum_path, "--regtest"]
        if offline:
            cmd.append("--offline")
        cmd += ["-D", self.datadir, *args]
        return subprocess.run(cmd, capture_output=True, text=True, check=True)

    def start(self):
        # Pre-daemon commands run --offline.
        self._cli("setconfig", "log_to_file", "false", offline=True)
        self._cli("daemon", "-d", offline=True)
        self.daemon_started = True
        time.sleep(1.5)  # let RPC bind

    def stop(self):
        if self.daemon_started:
            try:
                self._cli("daemon", "stop")
            except subprocess.CalledProcessError:
                pass
            self.daemon_started = False
        if os.path.exists(self.datadir):
            shutil.rmtree(self.datadir, ignore_errors=True)

    def cleanup(self, *args, **kwargs):
        self.stop()

    def imported_addr_wallet(self, addr, name="paper"):
        # Create and load a watch-only imported-address wallet. Returns the
        # name; Electrum picks the actual on-disk location based on --regtest.
        self._cli("restore", addr, "-w", name)
        self._cli("load_wallet", "-w", name)
        return name

    def addtransaction(self, wallet, tx_hex):
        # Feed a raw transaction so the wallet sees its UTXOs without a server.
        self._cli("addtransaction", tx_hex, "-w", wallet)

    def payto_unsigned_psbt(self, wallet, dest, amount, feerate=5):
        # Build an unsigned PSBT spending to `dest`. Returns base64 PSBT.
        # Offline daemon has no fee oracle, so we pass an explicit feerate
        # (sat/byte). RBF is on by default in Electrum 4.7+.
        r = self._cli("payto", dest, str(amount),
                      "--unsigned", "--feerate", str(feerate),
                      "-w", wallet)
        # Electrum CLI wraps strings in quotes; strip them.
        return r.stdout.strip().strip('"')

    @staticmethod
    def create(*args, **kwargs):
        e = Electrum(*args, **kwargs)
        e.start()
        return e


def _find_electrum():
    # Resolve the `electrum` binary, in order:
    #   1. ELECTRUM_BIN env var — for users with a venv install
    #      (e.g. ELECTRUM_BIN=/home/me/electrum/ENV/bin/electrum)
    #   2. `electrum` on PATH
    path = os.environ.get("ELECTRUM_BIN") or shutil.which("electrum")
    if path and os.path.isfile(path) and os.access(path, os.X_OK):
        return path
    return None


@pytest.fixture
def electrum():
    # Electrum 4.7+ daemon in --regtest --offline mode.
    # Skips if no usable binary — set ELECTRUM_BIN to point at one.
    path = _find_electrum()
    if not path:
        pytest.skip("electrum not found — set $ELECTRUM_BIN or put it on PATH")
    e = Electrum.create(path)
    yield e
    e.stop()

# EOF
