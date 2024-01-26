# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# imptask.py -- important async tasks that shouldn't die
# 
import sys, uasyncio, ckcc

def die_with_debug(exc):
    try:
        is_debug = ckcc.vcp_enabled(None) or ckcc.is_debug_build()
    except:
        # robustness
        is_debug = False

    if is_debug and isinstance(exc, KeyboardInterrupt):
        # preserve GUI state, but want to see where we are
        print("KeyboardInterrupt")
        raise exc
    elif isinstance(exc, SystemExit):
        # Ctrl-D and warm reboot cause this, not bugs
        raise exc
    else:
        # show stacktrace for debug photos
        try:
            import uio, ux
            tmp = uio.StringIO()
            sys.print_exception(exc, tmp)
            msg = tmp.getvalue()
            del tmp
            print(msg)
            ux.show_fatal_error(msg)
        except: pass

        # securely die (wipe memory)
        if not is_debug:
            try:
                import callgate
                callgate.show_logout(1)
            except: pass

class ImportantTask:
    def __init__(self):
        self.tasks = dict()

        uasyncio.get_event_loop().set_exception_handler(self.handle_exc)

    def handle_exc(self, loop, context):
        # Unhandled exception in a task.
        task = context['future']

        # See if it matters: some tasks are short-lived and exception in them
        # may not be fatal or even serious
        for name, t in self.tasks.items():
            if t == task:
                print("Panic stop: %r has died" % name)
                die_with_debug(context["exception"])
                # not reached, except on simulator:
                break
        else:
            # uncaught exception in an unnamed (and unimportant) task
            print("UNNAMED: " + context["message"])
            sys.print_exception(context["exception"])
            print("... future: %r" % context.get("future", '?'))

    def start_task(self, name, awaitable):
        # start a critical task and watch for it to never die
        print("Start: %s" % name)
        task = uasyncio.create_task(awaitable)
        self.tasks[name] = task
        return task

    def task_name(self, t):
        for k, v in self.tasks.items():
            if v == t:
                return k
        return None

IMPT = ImportantTask()

# EOF
