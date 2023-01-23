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
                ['-m', plugin.mark, '--collect-only', "--no-header", "--no-summary"], plugins=[plugin]
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


def _run_tests_with_simulator(test_module: str, simulator_args: List[str], pytest_marks: str, pytest_k: str,
                              pdb: bool, failed_first: bool) -> ExitCode:
    sim = ColdcardSimulator(args=simulator_args)
    sim.start()
    time.sleep(1)
    cmd_list = [
        "--cache-clear", "-m", pytest_marks, "--sim", test_module if test_module is not None else ""
    ]
    if pytest_k:
        cmd_list += ["-k", pytest_k]
    if pdb:
        cmd_list.append("--pdb")
    if failed_first:
        cmd_list.append("--ff")
    exit_code = pytest.main(cmd_list)
    sim.stop()
    time.sleep(1)
    clean_sim_data()  # clean up work
    remove_client_sockets()
    return exit_code


def run_tests_with_simulator(test_module=None, simulator_args=None, pytest_marks="not onetime and not veryslow and not manual",
                             pytest_k=None, pdb=False, failed_first=False):
    failed = []
    exit_code = _run_tests_with_simulator(test_module, simulator_args, pytest_marks, pytest_k, pdb, failed_first)
    if not is_ok(exit_code):
        # no success, no nothing - give failed another try, each alone with its own simulator
        last_failed = get_last_failed()
        print("Running failed from last run", last_failed)
        exit_codes = []
        for failed_test in last_failed:
            exit_code_2 = _run_tests_with_simulator(failed_test, simulator_args, pytest_marks, pytest_k, pdb, failed_first)
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
    def __init__(self, path=None, args=None):
        self.proc = None
        self.args = args
        self.path = "/tmp/ckcc-simulator.sock" if path is None else path

    def start(self):
        # here we are in testing directory
        cmd_list = [
            "python",
            "simulator.py"
        ]
        if self.args is not None:
            cmd_list.extend(self.args)

        self.proc = subprocess.Popen(
            cmd_list,
            # this needs to be in firmware/unix - expected to be run from firmware/testing
            cwd="../unix",
            preexec_fn=os.setsid
        )
        time.sleep(SIM_INIT_WAIT)
        atexit.register(self.stop)

    def stop(self):
        pp = self.proc.poll()
        if pp is None:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            os.waitpid(os.getpgid(self.proc.pid), 0)

        atexit.unregister(self.stop)


def main():
    parser = argparse.ArgumentParser(description="Run tests against simulated Coldcard")
    parser.add_argument("-w", "--sim-init-wait", type=int, help="Choose how much to sleep after simulator is started")
    parser.add_argument("-m", "--module", action="append", help="Choose only n modules to run")
    parser.add_argument("--pdb", action="store_true", help="Go to debugger on failure")
    parser.add_argument("--ff", action="store_true", help="Run the last failures first")
    parser.add_argument("--onetime", action="store_true", default=False, help="run tests marked as 'onetime'")
    parser.add_argument("--veryslow", action="store_true", default=False, help="run tests marked as 'veryslow'")
    parser.add_argument("--collect", type=str, metavar="MARK", help="Collect marked test and print them to stdout")
    parser.add_argument("-k", "--pytest-k", type=str, metavar="EXPRESSION", default=None, help="only run tests which match the given substring expression")
    args = parser.parse_args()

    if args.sim_init_wait:
        global SIM_INIT_WAIT
        SIM_INIT_WAIT = args.sim_init_wait

    if args.collect:
        # when collect is in argument - do just collect and exit
        print(collect_marked_tests(args.collect))
        return
    if args.module is None and (args.onetime is False and args.veryslow is False):
        args.module = ["all"]
    DEFAULT_SIMULATOR_ARGS = ["--eff", "--set", "nfc=1"]
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
        if test_module == "test_bsms.py":
            test_args = DEFAULT_SIMULATOR_ARGS + ["--set", "vidsk=1"]
        if test_module == "test_address_explorer.py":
            test_args = DEFAULT_SIMULATOR_ARGS + ["--set", "vidsk=1"]
        if test_module == "test_export.py":
            test_args = DEFAULT_SIMULATOR_ARGS + ["--set", "vidsk=1"]
        if test_module == "test_multisig.py":
            test_args = DEFAULT_SIMULATOR_ARGS + ["--set", "vidsk=1"]
        if test_module == "test_vdisk.py":
            test_args = ["--eject"] + DEFAULT_SIMULATOR_ARGS + ["--set", "vidsk=1"]
        if test_module == "test_bip39pw.py":
            test_args = []
        if test_module == "test_unit.py":
            test_args = ["--set", "nfc=1"]  # test_nvram_mk4 needs to run without --eff
        ec, failed_tests = run_tests_with_simulator(test_module, simulator_args=test_args, pytest_k=args.pytest_k,
                                                    pdb=args.pdb, failed_first=args.ff)
        result.append((test_module, ec, failed_tests))
        print("Done", test_module)
        print(80 * "=")

    # run veryslow is specified
    if args.veryslow:
        print("started veryslow tests")
        ec, failed_tests = run_tests_with_simulator(test_module=None, simulator_args=DEFAULT_SIMULATOR_ARGS,
                                                    pytest_marks="veryslow", pytest_k=args.pytest_k, pdb=args.pdb,
                                                    failed_first=args.ff)
        result.append(("veryslow", ec, failed_tests))
    # run onetime is specified (each test against its own simulator)
    if args.onetime:
        print("started onetime tests")
        onetime_tests = collect_marked_tests("onetime")
        for onetime_test in onetime_tests:
            ec, failed_tests = run_tests_with_simulator(test_module=onetime_test, simulator_args=DEFAULT_SIMULATOR_ARGS,
                                                        pytest_marks="onetime", pdb=args.pdb, failed_first=args.ff)
            result.append((f"onetime: {onetime_test}", ec, failed_tests))
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
