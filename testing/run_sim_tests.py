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

Testing on multiple simulators in parallel

python run_sim_tests.py --q1 --multiproc                                  # to run all Q tests in parallel (default num-proc=14 simulators)
python run_sim_tests.py --multiproc --num-proc 6                          # to run all Mk4 tests in parallel max 6 simulators at once
python run_sim_tests.py -m test_addr.py -m test_bbqr.py --multiproc       # just desired test
python run_sim_tests.py --q1 -m test_sign.py --multiproc                  # just desired test
python run_sim_tests --multiproc --turbo                                  # turbo causes both Mk4 & Q tests to run simultaneously (turbo doubles num-procs)
python run_sim_tests --multiproc --turbo                                  # all Mk4 & Q tests run in 60 minutes total!!
python run_sim_tests --multiproc --turbo -m test_addr.py -m test_ux.py    # will spawn 4 simulators: one Q and one Mk4 for address tests & one Q and one Mk4 for ux tests

Console output has some useful info:
* when job is started it will print its PID
* when job is done you'll get elapsed time from start (test duration)
* when all is done - complete test session duration

```
$ python run_sim_tests.py -m test_addr.py -m test_drv_entro.py -m test_usb.py --multiproc --turbo
started: Mk4   test_addr.py                  38824
started: Q     test_addr.py                  38935
started: Mk4   test_drv_entro.py             39042
started: Q     test_drv_entro.py             39150
started: Mk4   test_usb.py                   39257
started: Q     test_usb.py                   39364
done:    Mk4   test_usb.py                   0:00:06.043072
done:    Q     test_usb.py                   0:00:06.081147
done:    Mk4   test_addr.py                  0:00:51.141250
done:    Q     test_addr.py                  0:01:03.185571
done:    Mk4   test_drv_entro.py             0:03:24.234521
done:    Q     test_drv_entro.py             0:03:30.278795


elapsed: 0:03:50.308146
```

After jobs are finished, or even during execution you can inspect `/tmp/cc-simulators` directory:
* contains simulator work directories named as <PID> of specific simulator
* log directories where pytest output is piped
    * mk4_logs
    * q1_logs

```
$ pwd
/tmp/cc-simulators
$ ls
38824  38935  39042  39150  39257  39364  mk4_logs  q1_logs
$ ls 39042/*
39042/debug:
last-qr.png

39042/MicroSD:
drv-hex-idx0-2.txt  drv-pw-idx0.txt   drv-words-idx0-2.txt  drv-words-idx0.txt
drv-hex-idx0.txt    drv-wif-idx0.txt  drv-words-idx0-3.txt  drv-xprv-idx0.txt

39042/settings:

39042/VirtDisk:
README.md
$ ls mk4_logs/
test_addr.py.log  test_drv_entro.py.log  test_usb.py.log
```

To parse only failures use below cmd in {mk4,q1}_logs directory:
```
for f in $(ls); do x=`grep -n "short test summary info" $f | grep -Eo '^[^:]+'`; if [ -n "$x" ];then tail -n +"$x" $f | grep -E '^FAILED|^ERROR';fi ;done
```
"""

import os, time, glob, json, pytest, atexit, signal, argparse, subprocess, contextlib, shutil
from datetime import timedelta
from typing import List
from pytest import ExitCode


SIM_INIT_WAIT = 2  # 2 seconds, can be tweaked via cmdline arguments ( -w 6 )
DEFAULT_PYTEST_MARKS = "not onetime and not veryslow and not manual"

@contextlib.contextmanager
def pushd(new_dir):
    previous_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(previous_dir)

def clean_directory(pth):
    for root, dirs, files in os.walk(pth):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

def remove_all_client_sockets():
    with pushd("/tmp"):
        for fn in glob.glob("ckcc-client*.sock"):
            os.remove(fn)

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
               failed_first: bool, psbt2=False, is_Q=False, headless=False, sim_socket=None) -> ExitCode:
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
    if sim_socket:
        cmd_list.append("--sim-socket")
        cmd_list.append(sim_socket)

    return pytest.main(cmd_list)

def _run_coldcard_tests(test_module: str, simulator_args: List[str],
                        pytest_k: str, pdb: bool, failed_first: bool, psbt2=False,
                        is_Q=False, headless=False, pytest_marks: str = DEFAULT_PYTEST_MARKS,
                        sim_segregate=False) -> ExitCode:
    sock_path = None
    if simulator_args is not None:
        sim = ColdcardSimulator(args=simulator_args, headless=headless, segregate=sim_segregate)
        sim.start()
        time.sleep(1)
        sock_path = sim.socket

    exit_code = _run_pytest_tests(test_module, pytest_marks, pytest_k, pdb,
                                  failed_first, psbt2, is_Q, headless, sock_path)

    if simulator_args is not None:
        sim.stop()
        time.sleep(1)
        clean_sim_data()
        remove_all_client_sockets()

    return exit_code


def run_coldcard_tests(test_module=None, simulator_args=None, pytest_k=None, pdb=False,
                       failed_first=False, psbt2=False, is_Q=False, headless=False,
                       pytest_marks=DEFAULT_PYTEST_MARKS):
    failed = []
    exit_code = _run_coldcard_tests(test_module, simulator_args, pytest_k,
                                    pdb, failed_first, psbt2, is_Q, headless, pytest_marks)
    if not is_ok(exit_code):
        # no success, no nothing - give failed another try, each alone with its own simulator
        last_failed = get_last_failed()
        print("Running failed from last run", last_failed)
        exit_codes = []
        for failed_test in last_failed:
            exit_code_2 = _run_coldcard_tests(failed_test, simulator_args,
                                              pytest_k, pdb, failed_first, psbt2, is_Q,
                                              headless, pytest_marks)
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
    def __init__(self,args=None, headless=False, segregate=False):
        self.proc = None
        self.args = args
        self.headless = headless
        self.segregate = segregate
        self.socket = "/tmp/ckcc-simulator.sock"

    def start(self, start_wait=None):
        # here we are in testing directory
        cmd_list = [
            "python", "simulator.py"
        ]
        if self.args is not None:
            cmd_list.extend(self.args)
        if self.headless:
            cmd_list.append("--headless")
        if self.segregate:
            cmd_list.append("--segregate")

        self.proc = subprocess.Popen(
            cmd_list,
            # this needs to be in firmware/unix - expected to be run from firmware/testing
            cwd="../unix",
            preexec_fn=os.setsid,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(start_wait or SIM_INIT_WAIT)
        if self.segregate:
            self.socket = "/tmp/ckcc-simulator-%d.sock" % self.proc.pid
        atexit.register(self.stop)

    def stop(self):
        pp = self.proc.poll()
        if pp is None:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            os.waitpid(os.getpgid(self.proc.pid), 0)

        atexit.unregister(self.stop)


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
    parser.add_argument("--multiproc", action="store_true", default=False,
                        help="Run tests & simulators in parallel")
    parser.add_argument("--num-proc", type=int, default=16,
                        help="How many executors/simulators to run in parallel in --multiproc mode")
    parser.add_argument("--turbo", action="store_true", default=False,
                        help="Both Mk4 and Q at the same time")
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
        test_modules = glob.glob("test_*.py")
        assert test_modules, "please run in ../testing subdir"
    else:
        for fn in args.module:
            if not os.path.exists(fn):
                raise RuntimeError(f"{fn} does not exist")
        test_modules = args.module

    # test_pincodes.py can only be run against real device
    # test_rng.py not needed when using simulator
    # test_rolls.py should be run alone as it does not need simulator
    # set diff
    test_modules = set(test_modules) - {"test_rng.py", "test_pincodes.py", "test_rolls.py"}

    module_args = []
    for test_module in sorted(list(test_modules)):
        sim_args = DEFAULT_SIMULATOR_ARGS
        if test_module in ["test_bsms.py", "test_address_explorer.py", "test_export.py",
                           "test_multisig.py", "test_ux.py"]:
            sim_args = DEFAULT_SIMULATOR_ARGS + ["--set", "vidsk=1"]
        if test_module == "test_vdisk.py":
            sim_args = ["--eject"] + DEFAULT_SIMULATOR_ARGS + ["--set", "vidsk=1"]
        if test_module == "test_bip39pw.py":
            sim_args = []
        if test_module in ["test_unit.py", "test_se2.py", "test_backup.py", "test_teleport.py"]:
            # test_nvram_mk4 needs to run without --eff
            # se2 duress wallet activated as ephemeral seed requires proper `settings.load`
            sim_args = ["--set", "nfc=1"]
        if test_module in ["test_ephemeral.py", "test_notes.py", "test_ccc.py"]:
            # proper `settings.load` _ virtual disk
            sim_args = ["--set", "nfc=1", "--set", "vidsk=1"]

        if args.q1 and '--q1' not in sim_args:
            sim_args.append('--q1')

        module_args.append((test_module, sim_args, args.pytest_k, args.pdb,
                            args.ff, args.psbt2, args.q1, args.headless))

    if args.multiproc:
        start_time = time.time()
        def add_to_queue(module_name, simulator_args, queue):
            if module_name == "test_miniscript.py":
                queue.append((2, [module_name, simulator_args, "not liana_miniscripts_simple and not test_tapscript and not test_bitcoind_tapscript_address and not test_minitapscript", ""]))
                queue.append((0, [module_name, simulator_args, "liana_miniscripts_simple", "-sep1"]))
                queue.append((2, [module_name, simulator_args, "test_tapscript", "-sep2"]))
                queue.append((0, [module_name, simulator_args, "test_bitcoind_tapscript_address", "-sep3"]))
                queue.append((0, [module_name, simulator_args, "test_minitapscript", "-sep4"]))

            elif module_name == "test_multisig.py":
                # split takes too much time
                queue.append((0, [module_name, simulator_args, "not tutorial and not airgapped and not ms_address and not descriptor_export", ""]))
                queue.append((0, [module_name, simulator_args, "airgapped", "-sep1"]))
                queue.append((0, [module_name, simulator_args, "tutorial", "-sep2"]))
                queue.append((0, [module_name, simulator_args, "ms_address", "-sep3"]))
                queue.append((0, [module_name, simulator_args, "descriptor_export", "-sep4"]))

            elif module_name == "test_seed_xor.py":
                # split takes too much time
                queue.append((0, [module_name, simulator_args, "test_import_xor", "-sep1"]))
                queue.append((0, [module_name, simulator_args, "not test_import_xor", ""]))

            elif module_name in ["test_export.py", "test_ephemeral.py", "test_sign.py", "test_msg.py",
                                 "test_backup.py", "test_bsms.py"]:
                # higher priority
                queue.append((1, [module_name, simulator_args, None, ""]))

            else:
                # standard priority
                queue.append((2, [module_name, simulator_args, None, ""]))

        # will clear everything there from previous runs
        tmp_dir = "/tmp/cc-simulators"
        clean_directory(tmp_dir)  # clean it
        mk4_log_dir = f"{tmp_dir}/mk4_logs"
        q1_log_dir = f"{tmp_dir}/q1_logs"
        os.makedirs(mk4_log_dir, exist_ok=True)
        os.makedirs(q1_log_dir, exist_ok=True)

        q = []  # build priority queue
        for mod_name, sim_args, *_ in module_args:
            if args.turbo:
                if "--q1" in sim_args:
                    add_to_queue(mod_name, sim_args, q)
                    add_to_queue(mod_name, [i for i in sim_args if i == "--q1"], q)
                else:
                    add_to_queue(mod_name, sim_args, q)
                    add_to_queue(mod_name, sim_args + ["--q1"], q)

            else:
                add_to_queue(mod_name, sim_args, q)

        # sort queue by priority, highest priority elements at the end
        q = [i[1] for i in sorted(q, reverse=True)]

        num_proc = args.num_proc
        if args.turbo:
            # double num-proc
            num_proc *= 2

        procs = []
        while True:
            # create as many processes as allowed by --num-proc (default=14)
            if q and (len(procs) < num_proc):
                # start simulators first
                q_chunks = []
                for _ in range (num_proc - len(procs)):
                    try:
                        mn, sim_args, k, mod_add = q.pop()  # remove element
                    except IndexError:
                        # priority queue is empty
                        break
                    sim = ColdcardSimulator(sim_args, segregate=True)
                    sim.start(start_wait=0)
                    ld = q1_log_dir if "--q1" in sim_args else mk4_log_dir
                    q_chunks.append((sim, mn, mod_add, k, ld))

                time.sleep(5)
                for sim, mn, mod_add, k, log_dir in q_chunks:
                    assert sim.socket
                    out_log_path = f"{log_dir}/%s.log" % (mn + mod_add)
                    out_fd = open(out_log_path, "w")
                    cmd_list = ["pytest", "--cache-clear", "-m", DEFAULT_PYTEST_MARKS, "--sim",
                                mn, "--sim-socket", sim.socket]
                    if k:
                        cmd_list.extend(["-k", k])
                    p = subprocess.Popen(cmd_list, preexec_fn=os.setsid, stdout=out_fd, stderr=out_fd)
                    mark = "Q" if "q1" in log_dir else "Mk4"
                    procs.append((mn+mod_add, p, out_fd, sim, mark, time.time()))
                    print(f'started: {mark:<6}{mn+mod_add:<30}{sim.socket.split("-")[-1].split(".")[0]:<10}')

            if not procs and not q:
                # done
                break

            i = 0
            while i < len(procs):
                mn, p, out_fd, sim, mark, st = procs[i]
                if p.poll() is None:
                    # still running
                    i += 1
                    continue
                else:
                    # done
                    p.communicate()
                    out_fd.close()
                    sim.stop()
                    del procs[i]
                    print(f"done:    {mark:<6}{mn:<30}{str(timedelta(seconds=time.time()-st)):<15}")

            time.sleep(3)

        # multiprocess done
        print(f"\n\nelapsed: {str(timedelta(seconds=time.time()-start_time))}")
        return

    result = []
    for arguments in module_args:
        test_module = arguments[0]
        print("Started", test_module)
        ec, failed_tests = run_coldcard_tests(*arguments)
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
    # sim = ColdcardSimulator(args=["--eff", "--segregate"])
    # sim.start()
    # import pdb;pdb.set_trace()
    # x = 5
# EOF
