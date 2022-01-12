import os
import re
# import shutil
from bdscan import globals
# import sys
import tempfile
# import json
# import globals
from lxml import etree

import xml.etree.ElementTree as ET

# from BlackDuckUtils import run_detect
from BlackDuckUtils import Utils
# from BlackDuckUtils import BlackDuckOutput as bo


class MyTreeBuilder(ET.TreeBuilder):
    def comment(self, data):
        self.start(ET.Comment, {})
        self.data(data)
        self.end(ET.Comment)


def parse_component_id(component_id):
    # Example: maven:org.springframework:spring-webmvc:4.2.3.RELEASE
    comp_ns = component_id.split(':')[0]
    comp_name_and_version = component_id.split(':')[1]
    comp_name = comp_name_and_version.split('/')[0]
    comp_version = comp_name_and_version.split('/')[1]

    return comp_ns, comp_name, comp_version


def convert_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id)
    # bdio_name = "http:" + component_id
    return bdio_name


def upgrade_nuget_dependency(package_files, component_name, current_version, upgrade_version):
    # Key will be actual name, value will be local filename
    files_to_patch = dict()

    # dirname = tempfile.TemporaryDirectory()
    tempdirname = tempfile.mkdtemp(prefix="snps-patch-" + component_name + "-" + upgrade_version)

    for package_file in package_files:
        # Todo: Manage sub-folders

        tree = etree.parse(package_file)
        root = tree.getroot()

        namespaces = {'ns': 'http://schemas.microsoft.com/developer/msbuild/2003'}
        myval = tree.xpath(f'.//PackageReference[@Include="{component_name}"][@Version="{current_version}"]',
                           namespaces=namespaces)
        if myval is not None:
            myval[0].attrib['Version'] = upgrade_version
        # tree = ET.parse(package_file)
        # root = tree.getroot()
        # elem = tree.findall(".//{http://schemas.microsoft.com/developer/msbuild/2003}ItemGroup")    # parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
        #
        # ET.register_namespace('', "http://schemas.microsoft.com/developer/msbuild/2003")
        # ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")
        #
        # tree = ET.parse(package_file, parser=ET.XMLParser(target=MyTreeBuilder()))
        # root = tree.getroot()
        #
        # nsmap = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}
        #
        # globals.printdebug(f"DEBUG: Search for nuget dependency {component_name}@{component_version}")
        #
        # for dep in root.findall('.//ItemGroup', nsmap):
        #     packageref = dep.find('PackageReference', nsmap)

            # # TODO Also include organization name?
            # if artifactId == component_name:
            #     globals.printdebug(f"DEBUG:   Found GroupId={groupId} ArtifactId={artifactId} Version={version}")
            #     dep.find('m:version', nsmap).text = component_version

        xmlstr = ET.tostring(root, encoding='utf8', method='xml')
        with open(tempdirname + "/" + package_file, "wb") as fp:
            fp.write(xmlstr)

        print(f"BD-Scan-Action: INFO: Updated Nuget component in: {package_file}")

        files_to_patch[package_file] = dirname + "/" + package_file

    return files_to_patch


def create_csproj(deps):
    if os.path.isfile('test.csproj'):
        print('BD-Scan-Action: ERROR: Maven test.csproj file already exists')
        return False

    dep_text = ''
    for dep in deps:
        groupid = dep[0]
        artifactid = dep[1]
        version = dep[2]

        dep_text += f'''    <PackageReference Include="{artifactid}" Version="{version}" />
'''

    proj_contents = f'''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>netcoreapp3.1</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    {dep_text}
  </ItemGroup>
</Project>'''
    try:
        with open('test.csproj', "w") as fp:
            fp.write(proj_contents)
    except Exception as e:
        print(e)
        return False
    return True


def attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, detect_connection_opts, bd,
                             upgrade_indirect, upgrade_major):
    # Need to test the short & long term upgrade guidance separately
    detect_connection_opts.append("--detect.blackduck.scan.mode=RAPID")
    detect_connection_opts.append("--detect.detector.buildless=true")
    detect_connection_opts.append("--detect.cleanup=false")

    # print('POSSIBLE UPGRADES NUGET:')
    # print(json.dumps(upgrade_dict, indent=4))

    # vulnerable_upgrade_list = []
    test_dirdeps = deps_list
    good_upgrades = {}
    for ind in range(0, 3):
        test_upgrade_list = []
        test_origdeps_list = []
        #
        # Look for upgrades to test
        for dep in test_dirdeps:
            if dep not in upgrade_dict.keys() or upgrade_dict[dep] is None or len(upgrade_dict[dep]) <= ind:
                continue
            upgrade_version = upgrade_dict[dep][ind]
            if upgrade_version == '':
                continue
            arr = dep.replace('/', ':').split(':')
            # forge = arr[0]
            groupid = arr[1]
            artifactid = arr[2]
            test_upgrade_list.append([groupid, artifactid, upgrade_version])
            test_origdeps_list.append(dep)

        if len(test_upgrade_list) == 0:
            # print('No upgrades to test')
            continue
        print(f'BD-Scan-Action: Cycle {ind + 1} - Validating {len(test_dirdeps)} potential upgrades')

        if not create_csproj(test_upgrade_list):
            return None

        output = False
        if globals.debug > 0:
            output = True
        pvurl, projname, vername, retval = Utils.run_detect(detect_jar, detect_connection_opts, output)

        if retval == 3:
            # Policy violation returned
            rapid_scan_data, dep_dict, direct_deps_vuln, pm = Utils.process_scan('upgrade-tests', bd, [], False, False)

            # print(f'MYDEBUG: Vuln direct deps = {direct_deps_vuln}')
            last_vulnerable_dirdeps = []
            for vulndep in direct_deps_vuln:
                arr = vulndep.split(':')
                compname = arr[2]
                #
                # find comp in depver_list
                for upgradedep, origdep in zip(test_upgrade_list, test_origdeps_list):
                    if upgradedep[1] == compname and upgrade_indirect:
                        # vulnerable_upgrade_list.append([origdep, upgradedep[2]])
                        last_vulnerable_dirdeps.append(origdep)
                        break
        elif retval != 0:
            # Other Detect failure - no upgrades determined
            last_vulnerable_dirdeps = []
            for upgradedep, origdep in zip(test_upgrade_list, test_origdeps_list):
                # vulnerable_upgrade_list.append([origdep, upgradedep[2]])
                last_vulnerable_dirdeps.append(origdep)
        else:
            # Detect returned 0
            # All tested upgrades not vulnerable
            last_vulnerable_dirdeps = []

        os.remove('test.csproj')

        # Process good upgrades
        for dep, upgrade in zip(test_origdeps_list, test_upgrade_list):
            if dep not in last_vulnerable_dirdeps:
                good_upgrades[dep] = upgrade[2]

        test_dirdeps = last_vulnerable_dirdeps

    return good_upgrades


def normalise_dep(dep):
    #
    # Replace / with :
    if dep.find('http:') == 0:
        dep = dep.replace('http:', '').replace('nuget/', 'nuget:')
    return dep


def get_projfile(projstring):
    import urllib.parse
    arr = projstring.split('/')
    if len(arr) < 4:
        return ''

    projfile = urllib.parse.unquote(arr[3])
    if os.path.isfile(projfile):
        print(f'Found project file {projfile}')
        return projfile
    return ''