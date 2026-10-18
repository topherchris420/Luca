#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import psutil
import time
import yaml
import sys
import os
from functools import reduce
import shutil
import re


def terminate_process(process):
    """
        Terminale all instances of a process defined by its name.
        :return: bool - status of the operation
    """
    terminated = False
    for proc in psutil.process_iter():
        if proc.name() == process:
            proc.terminate()
            if process == "hostapd":
                time.sleep(2)
            terminated = True
    return terminated


def read_config(path):
    """
        Read a value from the configuration
        :return: value (it can be any type)
    """
    dir = "/".join(sys.path[0].split("/")[:-2])
    config = yaml.load(open(os.path.join(dir, "config.yaml"), "r"),
                       Loader=yaml.SafeLoader)
    return reduce(dict.get, path, config)


def delete_captures():
    """
        Delete potential zombies capture directories
    """
    try:
        for d in os.listdir("/tmp/"):
            if re.match("[A-F0-9]{8}", d):
                shutil.rmtree(os.path.join("/tmp/", d))
        return True
    except:
        return False
