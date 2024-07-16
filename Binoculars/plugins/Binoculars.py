from Binoculars.config.config import loadconfig
from Binoculars.interface.interface import IDAAssistant

def PLUGIN_ENTRY():
    loadconfig()
    return IDAAssistant()