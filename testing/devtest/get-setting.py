import main
from main import settings
from ujson import dumps
RV.write(dumps(settings.get(main.SKEY)))

