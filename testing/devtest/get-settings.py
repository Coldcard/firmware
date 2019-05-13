from main import settings
from ujson import dumps
RV.write(dumps(settings.current))

