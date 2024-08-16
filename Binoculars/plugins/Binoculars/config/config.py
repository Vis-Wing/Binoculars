#!/usr/bin/env python  
# -*- coding:utf-8 _*-

import configparser
import os
import json

default_model = None
def loadconfig():
    from Binoculars.models.base import get_model
    global default_model
    default_model = get_model(readconfig('MODEL','Default_Model'))

def readconfig(section, key):
    config = os.path.join(os.path.split(os.path.realpath(__file__))[0], "config.ini")
    config_handle = configparser.ConfigParser()
    config_handle.read(config)
    return config_handle.get(section, key)

    
def writeconfig(section, key, content):
    config = os.path.join(os.path.split(os.path.realpath(__file__))[0], "config.ini")
    config_handle = configparser.ConfigParser()
    config_handle.read(config)
    config_handle.set(section,key,str(content))
    with open(config, 'w') as configfile:
        config_handle.write(configfile)
        
def readpromat(prompt):
    system_prompt = ""
    prompt = os.path.join(os.path.split(os.path.realpath(__file__))[0], prompt+".txt")
    with open(prompt) as prompt_handle:
        system_prompt = prompt_handle.read()
    return system_prompt

def get_model_list():
    config = os.path.join(os.path.split(os.path.realpath(__file__))[0], "model.ini")
    with open(config,"r") as file:
        return json.load(file)
        
def get_current_model():
    from Binoculars.models.base import get_model
    global default_model
    default_model = get_model(readconfig('MODEL','Default_Model'))
    return default_model
    
def get_current_language():
    import locale
    language, encoding = locale.getlocale()
    return language

