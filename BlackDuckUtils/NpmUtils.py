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
    comp_ns = component_id.split(':')[0]
    comp_name_and_version = component_id.split(':')[1]
    comp_name = comp_name_and_version.split('/')[0]
    comp_version = comp_name_and_version.split('/')[1]

    return comp_ns, comp_name, comp_version


def convert_dep_to_bdio(component_id):
    bdio_name = "http:" + re.sub(":", "/", component_id, 1)
    return bdio_name


def upgrade_npm_dependency(package_files, component_name, current_version, component_version):
    # Key will be actual name, value will be local filename

    files_to_patch = dict()
    # dirname = tempfile.TemporaryDirectory()
    tempdirname = tempfile.mkdtemp(prefix="snps-patch-" + component_name + "-" + component_version)
    origdir = os.getcwd()

    for package_file in package_files:
        os.chdir(origdir)
        if os.path.isabs(package_file):
            package_file = Utils.remove_cwd_from_filename(package_file)

        # Change into sub-folder for packagefile
        subtempdir = os.path.dirname(package_file)
        os.chdir(tempdirname)
        os.makedirs(subtempdir, exist_ok=True)
        os.chdir(subtempdir)

        print(f'DEBUG: upgrade_npm_dependency() - working in folder {os.getcwd()}')

        cmd = "npm install " + component_name + "@" + component_version
        print(f"BD-Scan-Action: INFO: Executing NPM to update component: {cmd}")
        err = os.system(cmd)
        if err > 0:
            print(f"BD-Scan-Action: ERROR: Error {err} executing NPM command")
            os.chdir(origdir)
            tempdirname.cleanup()
            return None

        os.chdir(origdir)
        # Keep files so we can commit them!
        # shutil.rmtree(dirname)

        files_to_patch["package.json"] = tempdirname + "/package.json"
        files_to_patch["package-lock.json"] = tempdirname + "/package-lock.json"

    return files_to_patch


def attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, detect_connection_opts, bd,
                             upgrade_indirect, upgrade_major):
    if shutil.which("npm") is None:
        print('BD-Scan-Action: ERROR: Unable to find npm executable to install packages - unable to test upgrades')
        return {}

    # Need to test the short & long term upgrade guidance separately
    detect_connection_opts.append("--detect.blackduck.scan.mode=RAPID")
    detect_connection_opts.append("--detect.output.path=upgrade-tests")
    detect_connection_opts.append("--detect.cleanup=false")

    globals.printdebug('POSSIBLE UPGRADES:')
    globals.printdebug(json.dumps(upgrade_dict, indent=4))

    # vulnerable_upgrade_list = []
    test_dirdeps = deps_list
    good_upgrades = {}
    for ind in range(0, 3):
        last_vulnerable_dirdeps = []
        #
        # Look for upgrades to test
        installed_packages = []
        orig_deps_processed = []
        for dep in test_dirdeps:
            forge, comp, ver = parse_component_id(dep)
            # arr = dep.split('/')
            # forge = arr[0]
            # # arr2 = arr[1].split(':')
            # comp = arr[1]
            # ver = arr[2]
            dstring = f'{forge}:{comp}/{ver}'
            globals.printdebug(f'Working on component {dstring}')
            if dstring not in upgrade_dict.keys() or len(upgrade_dict[dstring]) <= ind:
                globals.printdebug(f'No Upgrade {ind} available for {dstring}')
                continue

            upgrade_version = upgrade_dict[dstring][ind]
            if upgrade_version == '':
                globals.printdebug(f'Could not get upgrade version fro upgrade_dict[{dstring}][{ind}]')
                continue
            # print(f'DEBUG: Upgrade dep = {comp}@{version}')

            # cmd = f"npm install {comp}@{upgrade_version} --package-lock-only >/dev/null 2>&1"
            cmd = f"npm install {comp}@{upgrade_version} --package-lock-only"
            # print(cmd)
            ret = os.system(cmd)

            if ret == 0:
                installed_packages.append([comp, upgrade_version])
                orig_deps_processed.append(dep)
            else:
                globals.printdebug(f'npm install for {comp}@{upgrade_version} returned error')
                last_vulnerable_dirdeps.append(f"npmjs:{comp}/{upgrade_version}")

        if len(installed_packages) == 0:
            # print('No upgrades to test')
            continue
        print(f'BD-Scan-Action: Cycle {ind + 1} - Validating {len(installed_packages)} potential upgrades')

        output = False
        if globals.debug > 0:
            output = True
        pvurl, projname, vername, retval = Utils.run_detect(detect_jar, detect_connection_opts, output)

        if retval == 3:
            # Policy violation returned
            rapid_scan_data, dep_dict, direct_deps_vuln, pm = Utils.process_scan('upgrade-tests', bd, [], False, False)

            # print(f'MYDEBUG: Vuln direct deps = {direct_deps_vuln}')
            for vulndep in direct_deps_vuln.keys():
                arr = vulndep.replace('/', ':').split(':')
                compname = arr[1]
                #
                # find comp in depver_list
                for upgradepkg, origdep in zip(installed_packages, orig_deps_processed):
                    # print(f'MYDEBUG: {compname} is VULNERABLE - {upgradepkg}, {origdep}')
                    if upgradepkg[0] == compname and upgrade_indirect:
                        last_vulnerable_dirdeps.append(origdep)
                        break
        elif retval != 0:
            for upgradepkg, origdep in zip(installed_packages, orig_deps_processed):
                # print(f'MYDEBUG: {compname} is VULNERABLE - {upgradepkg}, {origdep}')
                last_vulnerable_dirdeps.append(origdep)
        else:
            # Detect returned 0
            # All tested upgrades not vulnerable
            pass

        if os.path.isfile('package.json'):
            os.remove('package.json')
        os.remove('package-lock.json')
        # rapid_scan_data = bo.get_rapid_scan_results('upgrade-tests', bd)

        # Process good upgrades
        for upgrade, origdep in zip(installed_packages, orig_deps_processed):
            if origdep not in last_vulnerable_dirdeps:
                good_upgrades[origdep] = upgrade[1]

        test_dirdeps = last_vulnerable_dirdeps

    return good_upgrades


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
