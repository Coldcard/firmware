# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
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


# EOF
