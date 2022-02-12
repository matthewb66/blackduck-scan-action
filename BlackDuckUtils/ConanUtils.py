import os
import re
import shutil

import tempfile
import json

from BlackDuckUtils import Utils
from bdscan import globals
# from BlackDuckUtils import BlackDuckOutput as bo


def parse_component_id(component_id):
    comp_ns = component_id.split(':')[0]
    comp_name_and_version = component_id.split(':')[1] # libiconv/1.16@_/_#05310dd310959552336b136c594ac562
    comp_name = comp_name_and_version.split('/')[0] # libiconv
    comp_version_and_hash = comp_name_and_version.split('/', 1)[1] # 1.16@_/_#05310dd310959552336b136c594ac562
    comp_version = comp_version_and_hash.split('@')[0] # 1.16
    comp_extra = comp_name_and_version.split('@')[1] # _/_#05310dd310959552336b136c594ac562

    return comp_ns, comp_name, comp_version


def parse_component_id_full(component_id):
    comp_ns = component_id.split(':')[0]
    comp_name_and_version = component_id.split(':')[1] # folly/2020.08.10.00@_/_#b1cadac6d4ce906933dc25583108f437
    comp_name = comp_name_and_version.split('/')[0] # folly
    comp_version_and_hash = comp_name_and_version.split('/', 1)[1]
    comp_version = comp_version_and_hash.split('@')[0]
    comp_extra = comp_name_and_version.split('@')[1]

    return comp_ns, comp_name, comp_version, comp_extra



def convert_dep_to_bdio(component_id):
    comp_ns, comp_name, comp_version, comp_extra = parse_component_id_full(component_id)
    if globals.debug: print(f"DEBUG: comp_extra={comp_extra}")
    bdio_name = f"http:{comp_ns}/{comp_name}/{comp_version}%40{comp_extra.replace('/', '%2F').replace('#', '%23')}"
    return bdio_name

def convert_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id)
    return bdio_name


def normalise_dep(dep):
    if dep.find('http:') == 0:
        dep = dep.replace('http:', '')
    return dep.replace('/', ':', 1).replace('%40', '@').replace('%2F', '/').replace('%23', '#')
