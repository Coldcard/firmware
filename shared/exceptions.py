# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# exceptions.py - Exceptions defined by us.
#

# Caution: limited ability in Micropython to override system exceptions.

# USB framing error
class FramingError(RuntimeError):
    pass

# never used
#class CCUserRefused(RuntimeError): pass

# Coldcard UX is busy with some other request
class CCBusyError(RuntimeError):
    pass

# HSM is blocking your action
class HSMDenied(RuntimeError):
    pass

class HSMCMDDisabled(RuntimeError):
    pass

# PSBT / transaction related
class FatalPSBTIssue(RuntimeError):
    pass

class FraudulentChangeOutput(FatalPSBTIssue):
    def __init__(self, out_idx, msg):
        super().__init__('Output#%d: %s' % (out_idx, msg))

class IncorrectUTXOAmount(FatalPSBTIssue):
    def __init__(self, in_idx, msg):
        super().__init__('Input#%d: %s' % (in_idx, msg))

# This signals the need to switch from current
# menu (or whatever) to show something new. The
# stack has already been updated, but the old 
# top-of-stack code was waiting for a key event.
#
class AbortInteraction(BaseException):
    pass

# Useful text to show user when we can't handle a QR
class QRDecodeExplained(ValueError):
    pass

# Text about the problem w/ a address during search
class UnknownAddressExplained(ValueError):
    pass

# We're not going to co-sign using CCC feature
class CCCPolicyViolationError(RuntimeError):
    pass

# EOF
