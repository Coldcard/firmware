# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import main
from glob import settings
from ujson import dumps
RV.write(dumps(settings.get(main.SKEY, main.DEFAULT)))

