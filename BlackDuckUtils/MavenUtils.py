import os
import re
# import shutil
from bdscan import globals
# import sys
import tempfile
# import json
# import globals

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
    # comp_org = component_id.split(':')[1]
    comp_name = component_id.split(':')[2]
    comp_version = component_id.split(':')[3]

    return comp_ns, comp_name, comp_version


def convert_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id)
    return bdio_name


def upgrade_maven_dependency(package_files, component_name, current_version, component_version):
    # Key will be actual name, value will be local filename
    files_to_patch = dict()

    # dirname = tempfile.TemporaryDirectory()
    tempdirname = tempfile.mkdtemp(prefix="snps-patch-" + component_name + "-" + component_version)

    for package_file in package_files:
        # dir = os.path.sep.join(package_file.split(os.path.sep)[:-1])
        parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))

        ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
        ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")

        tree = ET.parse(package_file, parser=ET.XMLParser(target=MyTreeBuilder()))
        root = tree.getroot()

        nsmap = {'m': 'http://maven.apache.org/POM/4.0.0'}

        # globals.printdebug(f"DEBUG: Search for maven dependency {component_name}@{component_version}")

        for dep in root.findall('.//m:dependencies/m:dependency', nsmap):
            groupId = dep.find('m:groupId', nsmap).text
            artifactId = dep.find('m:artifactId', nsmap).text
            verentry = dep.find('m:version', nsmap)
            if artifactId == component_name:
                if verentry is not None:
                    version = verentry.text
                    globals.printdebug(f"DEBUG:   Found GroupId={groupId} ArtifactId={artifactId} Version={version}")
                    verentry.text = component_version
                    break
                else:
                    # ToDo: Need to add version tag as it does not exist
                    new = ET.Element('version')
                    new.text = component_version
                    dep.append(new)
                    break

        # Change into sub-folder for packagefile
        subtempdir = os.path.dirname(package_file)
        os.makedirs(os.path.join(tempdirname, subtempdir), exist_ok=True)

        xmlstr = ET.tostring(root, encoding='UTF-8', method='xml')
        with open(os.path.join(tempdirname, package_file), "wb") as fp:
            fp.write(xmlstr)

        print(f"BD-Scan-Action: INFO: Updated Maven component in: {os.path.join(tempdirname, package_file)}")

        files_to_patch[package_file] = os.path.join(tempdirname, package_file)

    return files_to_patch


def create_pom(deps):
    if os.path.isfile('pom.xml'):
        print('BD-Scan-Action: ERROR: Maven pom.xml file already exists')
        return False

    dep_text = ''
    for dep in deps:
        groupid = dep[0]
        artifactid = dep[1]
        version = dep[2]

        dep_text += f'''    <dependency>
        <groupId>{groupid}</groupId>
        <artifactId>{artifactid}</artifactId>
        <version>{version}</version>
    </dependency>
'''

    pom_contents = f'''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>sec</groupId>
    <artifactId>test</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>

    <dependencies>
    {dep_text}
    </dependencies>
</project>'''
    try:
        with open('pom.xml', "w") as fp:
            fp.write(pom_contents)
    except Exception as e:
        print(e)
        return False
    return True


def attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, detect_connection_opts, bd,
                             upgrade_indirect, upgrade_major):
    # Need to test the short & long term upgrade guidance separately
    detect_connection_opts.append("--detect.blackduck.scan.mode=RAPID")
    detect_connection_opts.append("--detect.detector.buildless=true")
    # detect_connection_opts.append("--detect.maven.buildless.legacy.mode=false")
    detect_connection_opts.append(f"--detect.output.path=upgrade-tests")
    detect_connection_opts.append("--detect.cleanup=false")

    # print('POSSIBLE UPGRADES:')
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
            arr = dep.split(':')
            # forge = arr[0]
            groupid = arr[1]
            artifactid = arr[2]
            test_upgrade_list.append([groupid, artifactid, upgrade_version])
            test_origdeps_list.append(dep)

        if len(test_upgrade_list) == 0:
            # print('No upgrades to test')
            continue
        print(f'BD-Scan-Action: Cycle {ind + 1} - Validating {len(test_upgrade_list)} potential upgrades')

        if not create_pom(test_upgrade_list):
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
                    if upgradedep[1] == compname:
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

        os.remove('pom.xml')

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
        dep = dep.replace('http:', '')
    return dep.replace('/', ':')


def find_allpomfiles():
    import glob
    return glob.glob('**/pom.xml', recursive=True)


def get_projfile(entry, allpoms):
    foundpom = ''
    folderarr = entry.split('/')
    if len(folderarr) < 3:
        return ''

    folder = folderarr[-2]
    for pom in allpoms:
        arr = pom.split(os.path.sep)
        if len(arr) >= 2 and arr[-2] == folder:
            if os.path.isfile(pom):
                foundpom = pom
                break
    return foundpom


def get_pom_line(comp, ver, filename):
    # parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))

    ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
    ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")

    tree = ET.parse(filename, parser=ET.XMLParser(target=MyTreeBuilder()))
    root = tree.getroot()

    nsmap = {'m': 'http://maven.apache.org/POM/4.0.0'}

    # globals.printdebug(f"DEBUG: Search for maven dependency {comp}@{ver}")

    for dep in root.findall('.//m:dependencies/m:dependency', nsmap):
        groupId = dep.find('m:groupId', nsmap).text
        artifactId = dep.find('m:artifactId', nsmap).text
        version = ''
        verentry = dep.find('m:version', nsmap)
        if verentry is not None:
            version = verentry.text

        if artifactId == comp and version == '':
            globals.printdebug(f"DEBUG:   Found GroupId={groupId} ArtifactId={artifactId} NOVersion")
            return 1

        if artifactId == comp and version == ver:
            globals.printdebug(f"DEBUG:   Found GroupId={groupId} ArtifactId={artifactId} Version={version}")
            return 1

    return -1
