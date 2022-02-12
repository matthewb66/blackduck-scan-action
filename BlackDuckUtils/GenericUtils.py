import os
import re
import shutil

import tempfile
import json

from BlackDuckUtils import Utils
from bdscan import globals
# from BlackDuckUtils import BlackDuckOutput as bo


def parse_component_id(component_id):
    # Example: npmjs:trim-newlines/2.0.0
    # Example: crates:rand_core/0.5.0
    comp_ns = component_id.split(':')[0]
    comp_name_and_version = component_id.split(':')[1]
    comp_name = comp_name_and_version.split('/')[0]
    comp_version = comp_name_and_version.split('/')[1]

    return comp_ns, comp_name, comp_version


def convert_dep_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id, 1)
    return bdio_name


def normalise_dep(dep):
    #
    # Replace / with :
    # return dep.replace('/', ':').replace('http:', '')
    dep = dep.replace('http:', '').replace(':', '|').replace('/', '|')
    # Check format matches 'npmjs:component/version'
    slash = dep.split('|')
    if len(slash) == 3:
        return f"{slash[0]}:{slash[1]}/{slash[2]}"
    return ''
