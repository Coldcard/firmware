# abort menu system and return to top menu
from main import pa, numpad

pa.setup(pa.pin)
pa.login()

from actions import goto_top_menu
goto_top_menu()

numpad.abort_ux()
