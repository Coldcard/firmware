import sys, uos
from ubinascii import hexlify as b2a_hex
from files import CardSlot, CardMissingError

class AuditLogger:
    def __init__(self, dirname, digest, never_log):
        self.dirname = dirname
        self.digest = digest
        self.never_log = never_log

    def __enter__(self):
        try:
            if self.never_log:
                raise NotImplementedError

            self.card = CardSlot().__enter__()

            d  = self.card.get_sd_root() + '/' + self.dirname

            # mkdir if needed
            try: uos.stat(d)
            except: uos.mkdir(d)
                
            self.fname = d + '/' + b2a_hex(self.digest[-8:]).decode('ascii') + '.log'
            self.fd = open(self.fname, 'a+t')       # append mode
        except (CardMissingError, OSError, NotImplementedError):
            # may be fatal or not, depending on configuration
            self.fname = self.card = None
            self.fd = sys.stdout

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_value:
            self.fd.write('\n\n---- Coldcard Exception ----\n')
            sys.print_exception(exc_value, self.fd)

        self.fd.write('\n===\n\n')

        if self.card:
            assert self.fd != sys.stdout
            self.fd.close()
            self.card.__exit__(exc_type, exc_value, traceback)

    @property
    def is_unsaved(self):
        return not self.card

    def info(self, msg):
        print(msg, file=self.fd)
        #if self.fd != sys.stdout: print(msg)
