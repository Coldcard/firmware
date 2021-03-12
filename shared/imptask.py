# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# imptask.py -- important async tasks that shouldn't die
# 
import sys, uasyncio

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
                from main import die_with_debug
                die_with_debug(context["exception"])
                # not reached, except on simulator:
                break
        else:
            print("IMPTASK: " + context["message"])
            sys.print_exception(context["exception"])
            print("... ignoring that")

    def start_task(self, name, awaitable):
        # start a critical task and watch for it to never die
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
