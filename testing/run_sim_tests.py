# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.

"""
Run conveniently tests against simulator. Tests are run module after module. If any tests fail,
it will try to re-run those failed test with fresh simulator. Has to be run from firmware/testing directory.
Do not forget to comment/uncomment line in pytest.ini.

. ENV/bin/activate
python run_sim_tests.py --help
python run_sim_tests.py --veryslow                             # run ONLY very slow tests
python run_sim_tests.py --onetime                              # run ONLY onetime tests (each will get its own simulator)
python run_sim_tests.py --onetime --veryslow                   # run both onetime and very slow
python run_sim_tests.py -m test_nfc.py                         # run only nfc tests
python run_sim_tests.py -m test_nfc.py -m test_hsm.py          # run nfc and hsm tests
python run_sim_tests.py -m all                                 # run all tests but not onetime and not very slow (cca 40 minutes)
python run_sim_tests.py                                        # same as with '-m all' above --> most useful
python run_sim_tests.py -m all --onetime --veryslow            # run all tests (cca 252 minutes)
python run_sim_tests.py -m test_multisig.py -k cosigning       # run only tests that match expression from test_multisig.py
python run_sim_tests.py -m test_export.py --pdb                # run only export tests and attach debugger
python run_sim_tests.py -m test_attended.py --q1 -w 6 --login  # run attended test + all login tests
python run_sim_tests.py -w 6 --q1 --headless                   # run in headless mode (skips QR code checks)


Onetime/veryslow tests are completely separated form the rest of the test suite.
When using -m/--module do not expect the --onetime/--veryslow to apply. If --onetime/--veryslow
is specified, these test will run at the end or alone.

python run_sim_tests.py --collect onetime                      # just print all onetime tests to stdout
python run_sim_tests.py --collect veryslow                     # just print all veryslow tests to stdout
python run_sim_tests.py --collect manual                       # just print all manual tests to stdout

Make sure to run manual test if you want to state that your changes passed all the tests.
"""

import os, time, glob, json, pytest, atexit, signal, argparse, subprocess, contextlib
from typing import List

from pytest import ExitCode


SIM_INIT_WAIT = 2  # 2 seconds, can be tweaked via cmdline arguments ( -w 6 )


@contextlib.contextmanager
def pushd(new_dir):
    previous_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(previous_dir)


def remove_client_sockets():
    with pushd("/tmp"):
        for fn in glob.glob("ckcc-client*.sock"):
            os.remove(fn)
    print("Removed all client sockets")


def remove_cautious(fpath: str) -> None:
    if os.path.basename(fpath) in ["README.md", ".gitignore"]:
        # Do not remove README.md or .gitignore"
        return
    os.remove(fpath)


def clean_sim_data():
    with pushd("../unix/work"):
        for path, dirnames, filenames in os.walk("."):
            for filename in filenames:
                filepath = os.path.join(path, filename)
                remove_cautious(filepath)
    print("Work directory cleaned up")


def collect_marked_tests(mark: str) -> List[str]:
    plugin = PytestCollectMarked(mark=mark)
    with open(os.devnull, 'w') as dev_null:
        with contextlib.redirect_stdout(dev_null):
            pytest.main(
                ['-m', plugin.mark, '--collect-only', "--no-header", "--no-summary"],
                plugins=[plugin]
            )
    return plugin.collected


def get_last_failed() -> List[str]:
    with open(".pytest_cache/v/cache/lastfailed", "r") as f:
        res = f.read()
    last_failed = json.loads(res)
    return list(last_failed.keys())


def is_ok(ec: ExitCode) -> bool:
    if ec in [ExitCode.OK, ExitCode.NO_TESTS_COLLECTED]:
        return True
    return False


def _run_pytest_tests(test_module: str, pytest_marks: str, pytest_k: str, pdb: bool,
               failed_first: bool, psbt2=False, is_Q=False, headless=False) -> ExitCode:
    cmd_list = [
        "--cache-clear", "-m", pytest_marks, "--sim",
        test_module if test_module is not None else ""
    ]
    if pytest_k:
        cmd_list += ["-k", pytest_k]
    if pdb:
        cmd_list.append("--pdb")
    if failed_first:
        cmd_list.append("--ff")
    if psbt2:
        cmd_list.append("--psbt2")
    if is_Q:
        cmd_list.insert(0, "--Q")  # only changes behavior in login_settings_test
    if headless:
        cmd_list.append("--headless")

    return pytest.main(cmd_list)

def _run_coldcard_tests(test_module: str, simulator_args: List[str], pytest_marks: str,
                        pytest_k: str, pdb: bool, failed_first: bool, psbt2=False,
                        is_Q=False, headless=False) -> ExitCode:
    if simulator_args is not None:
        sim = ColdcardSimulator(args=simulator_args, headless=headless)
        sim.start()
        time.sleep(1)

    exit_code = _run_pytest_tests(test_module, pytest_marks, pytest_k, pdb,
                                  failed_first, psbt2, is_Q, headless)

    if simulator_args is not None:
        sim.stop()
        time.sleep(1)
        clean_sim_data()
    return exit_code


def run_coldcard_tests(test_module=None, simulator_args=None, pytest_k=None, pdb=False,
                       failed_first=False, psbt2=False, is_Q=False, headless=False,
                       pytest_marks="not onetime and not veryslow and not manual"):
    failed = []
    exit_code = _run_coldcard_tests(test_module, simulator_args, pytest_marks, pytest_k,
                                    pdb, failed_first, psbt2, is_Q, headless)
    if not is_ok(exit_code):
        # no success, no nothing - give failed another try, each alone with its own simulator
        last_failed = get_last_failed()
        print("Running failed from last run", last_failed)
        exit_codes = []
        for failed_test in last_failed:
            exit_code_2 = _run_coldcard_tests(failed_test, simulator_args, pytest_marks,
                                              pytest_k, pdb, failed_first, psbt2, is_Q,
                                              headless)
            exit_codes.append(exit_code_2)
            if not is_ok(exit_code_2):
                failed.append(failed_test)
        if all([ec == ExitCode.OK for ec in exit_codes]):
            exit_code = ExitCode.OK
    return exit_code, failed


class PytestCollectMarked:
    def __init__(self, mark):
        self.mark = mark
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        for item in items:
            for marker in item.own_markers:
                if marker.name == self.mark:
                    self.collected.append(item.nodeid)


class ColdcardSimulator:
    def __init__(self, path=None, args=None, headless=False):
        self.proc = None
        self.args = args
        self.path = "/tmp/ckcc-simulator.sock" if path is None else path
        self.headless = headless

    def start(self, start_wait=None):
        # here we are in testing directory
        cmd_list = [
            "python", "simulator.py"
        ]
        if self.args is not None:
            cmd_list.extend(self.args)
        if self.headless:
            cmd_list.append("--headless")

        self.proc = subprocess.Popen(
            cmd_list,
            # this needs to be in firmware/unix - expected to be run from firmware/testing
            cwd="../unix",
            preexec_fn=os.setsid
        )
        time.sleep(start_wait or SIM_INIT_WAIT)
        atexit.register(self.stop)

    def stop(self):
        pp = self.proc.poll()
        if pp is None:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            os.waitpid(os.getpgid(self.proc.pid), 0)

        atexit.unregister(self.stop)
        remove_client_sockets()


def main():
    parser = argparse.ArgumentParser(description="Run tests against simulated Coldcard")
    parser.add_argument("-w", "--sim-init-wait", type=int,
                        help="Choose how much to sleep after simulator is started")
    parser.add_argument("-m", "--module", action="append", help="Choose only n modules to run")
    parser.add_argument("--pdb", action="store_true", help="Go to debugger on failure")
    parser.add_argument("--q1", action="store_true", help="Simulate a Q instead of Mk COLDCARD")
    parser.add_argument("--psbt2", action="store_true", help="`fake_txn` produces PSBTv2")
    parser.add_argument("--ff", action="store_true", help="Run the last failures first")
    parser.add_argument("--onetime", action="store_true", default=False,
                        help="run tests marked as 'onetime'")
    parser.add_argument("--veryslow", action="store_true", default=False,
                        help="run 'login_settings_tests.py'")
    parser.add_argument("--login", action="store_true", default=False,
                        help="run 'login_settings_tests'")
    parser.add_argument("--clone", action="store_true", default=False,
                        help="run 'clone_tests'")
    parser.add_argument("--seedless", action="store_true", default=False,
                        help="run 'seedless_tests'")
    parser.add_argument("--collect", type=str, metavar="MARK",
                        help="Collect marked test and print them to stdout")
    parser.add_argument("-k", "--pytest-k", type=str, metavar="EXPRESSION", default=None,
                        help="only run tests which match the given substring expression")
    parser.add_argument("--headless", action="store_true", default=False,
                        help="run simulator instance in headless mode")
    args = parser.parse_args()

    if args.sim_init_wait:
        global SIM_INIT_WAIT
        SIM_INIT_WAIT = args.sim_init_wait

    if args.collect:
        # when collect is in argument - do just collect and exit
        print(collect_marked_tests(args.collect))
        return

    if args.module is None and (args.onetime is False
                                and args.veryslow is False
                                and args.login is False
                                and args.clone is False
                                and args.seedless is False):
        args.module = ["all"]

    DEFAULT_SIMULATOR_ARGS = ["--eff", "--set", "nfc=1"]
    if args.q1:
        DEFAULT_SIMULATOR_ARGS.append('--q1')

    if args.module is None:
        test_modules = []
    elif len(args.module) == 1 and args.module[0].lower() == "all":
        test_modules = sorted(glob.glob("test_*.py"))
        assert test_modules, "please run in ../testing subdir"
    else:
        for fn in args.module:
            if not os.path.exists(fn):
                raise RuntimeError(f"{fn} does not exist")
        test_modules = sorted(args.module)

    result = []
    for test_module in test_modules:
        test_args = DEFAULT_SIMULATOR_ARGS
        if test_module in ["test_rng.py", "test_pincodes.py", "test_rolls.py"]:
            # test_pincodes.py can only be run against real device
            # test_rng.py not needed when using simulator
            # test_rolls.py should be run alone as it does not need simulator
            print("Skipped", test_module)
            continue

        print("Started", test_module)
        if test_module in ["test_bsms.py", "test_address_explorer.py", "test_export.py",
                           "test_multisig.py", "test_ux.py"]:
            test_args = DEFAULT_SIMULATOR_ARGS + ["--set", "vidsk=1"]
        if test_module == "test_vdisk.py":
            test_args = ["--eject"] + DEFAULT_SIMULATOR_ARGS + ["--set", "vidsk=1"]
        if test_module == "test_bip39pw.py":
            test_args = []
        if test_module in ["test_unit.py", "test_se2.py", "test_backup.py"]:
            # test_nvram_mk4 needs to run without --eff
            # se2 duress wallet activated as ephemeral seed requires proper `settings.load`
            test_args = ["--set", "nfc=1"]
        if test_module in ["test_ephemeral.py", "test_notes.py"]:
            test_args = ["--set", "nfc=1", "--set", "vidsk=1"]

        if args.q1 and '--q1' not in test_args:
            test_args.append('--q1')

        ec, failed_tests = run_coldcard_tests(test_module, simulator_args=test_args,
                                              pytest_k=args.pytest_k, pdb=args.pdb,
                                              failed_first=args.ff, psbt2=args.psbt2,
                                              headless=args.headless)
        result.append((test_module, ec, failed_tests))
        print("Done", test_module)
        print(80 * "=")

    # run veryslow is specified
    if args.veryslow:
        print("started veryslow tests")
        ec, failed_tests = run_coldcard_tests(test_module=None, pytest_marks="veryslow",
                                              pytest_k=args.pytest_k, pdb=args.pdb,
                                              simulator_args=DEFAULT_SIMULATOR_ARGS,
                                              failed_first=args.ff, psbt2=args.psbt2,
                                              headless=args.headless)
        result.append(("veryslow", ec, failed_tests))

    # run onetime is specified (each test against its own simulator)
    if args.onetime:
        print("started onetime tests")
        onetime_tests = collect_marked_tests("onetime")
        for onetime_test in onetime_tests:
            ec, failed_tests = run_coldcard_tests(test_module=onetime_test, pdb=args.pdb,
                                                  failed_first=args.ff, pytest_marks="onetime",
                                                  simulator_args=DEFAULT_SIMULATOR_ARGS,
                                                  psbt2=args.psbt2, headless=args.headless)
            result.append((f"onetime: {onetime_test}", ec, failed_tests))

    if args.login:
        print("start login settings tests")
        ec, failed_tests = run_coldcard_tests(test_module="login_settings_tests.py", pdb=args.pdb,
                                              failed_first=args.ff, pytest_k=args.pytest_k,
                                              is_Q=True if args.q1 else False,
                                              headless=args.headless)
        result.append((f"login_settings_tests", ec, failed_tests))

    if args.clone:
        print("start clone tests")
        ec, failed_tests = run_coldcard_tests(test_module="clone_tests.py", pdb=args.pdb,
                                              failed_first=args.ff, pytest_k=args.pytest_k,
                                              headless=args.headless)
        result.append((f"clone_tests", ec, failed_tests))

    if args.seedless:
        print("start seedless tests")
        ec, failed_tests = run_coldcard_tests(test_module="seedless_tests.py", pdb=args.pdb,
                                              failed_first=args.ff, pytest_k=args.pytest_k,
                                              headless=args.headless)
        result.append((f"seedless_tests", ec, failed_tests))

    print("All done")

    any_failed = False
    for module, ec, failed in result:
        if not failed:
            continue
        print(f"FAILED {module:40s} {failed}")
        any_failed = True

    if any_failed is False:
        print("SUCCESS")

    print()


if __name__ == "__main__":
    main()

# EOF
