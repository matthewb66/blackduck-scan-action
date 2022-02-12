import os
import re
import shutil

import tempfile
import json

from BlackDuckUtils import Utils
from bdscan import globals
# from BlackDuckUtils import BlackDuckOutput as bo


def parse_component_id(component_id):
    # Example: golang:github.com/gin-gonic/gin/render:v1.2
    comp_ns = component_id.split(':')[0]
    comp_name = component_id.split(':')[1]
    comp_version = component_id.split(':')[2]

    return comp_ns, comp_name, comp_version


def convert_dep_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id.replace('/', '%2F')) #, 1
    return bdio_name

def convert_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id)
    return bdio_name


def normalise_dep(dep):
    #
    # Replace / with :
    if dep.find('http:') == 0:
        dep = dep.replace('http:', '')
    return dep.replace('/', ':')
