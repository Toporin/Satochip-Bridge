print('In SatochipBridge __init__ A')

from .version import SATOCHIP_BRIDGE_VERSION
from .SatochipBridge import SatochipBridge
from .Client import Client
from .handler import HandlerTxt, HandlerSimpleGUI

print('In SatochipBridge __init__ B')

__version__ = SATOCHIP_BRIDGE_VERSION 
