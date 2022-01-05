import os
import re
import shutil

# import globals
import tempfile
# import json

from BlackDuckUtils import Utils as bu
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


def upgrade_npm_dependency(package_file, component_name, current_version, component_version):
    # Key will be actual name, value will be local filename
    if package_file.endswith('Unknown'):
        return None

    files_to_patch = dict()

    # dirname = tempfile.TemporaryDirectory()
    dirname = tempfile.mkdtemp(prefix="snps-patch-" + component_name + "-" + component_version)
    print(f"DEBUG: dirname is: {dirname}")
    print(f"DEBUG: copied {package_file} to {shutil.copy2(package_file, dirname + '/' + package_file)}")

    origdir = os.getcwd()
    os.chdir(dirname)
    print(f"DEBUG: changed folder to {os.getcwd()}")

    cmd = "npm install " + component_name + "@" + component_version
    print(f"INFO: Executing NPM to update component: {cmd}")
    err = os.system(cmd)
    if err > 0:
        print(f"ERROR: Error {err} executing NPM command")
        os.chdir(origdir)
        dirname.cleanup()
        return None

    os.chdir(origdir)
    # Keep files so we can commit them!
    # shutil.rmtree(dirname)

    files_to_patch["package.json"] = dirname + "/package.json"
    files_to_patch["package-lock.json"] = dirname + "/package-lock.json"

    return files_to_patch


def attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, detect_connection_opts, bd,
                             upgrade_indirect, upgrade_major):
    # Need to test the short & long term upgrade guidance separately
    detect_connection_opts.append("--detect.blackduck.scan.mode=RAPID")
    detect_connection_opts.append("--detect.output.path=upgrade-tests")
    detect_connection_opts.append("--detect.cleanup=false")

    # print('POSSIBLE UPGRADES:')
    # print(json.dumps(upgrade_dict, indent=4))

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
            if dstring not in upgrade_dict.keys() or len(upgrade_dict[dstring]) <= ind:
                # print(f'No Upgrade {ind} available for {dstring}')
                continue

            upgrade_version = upgrade_dict[dstring][ind]
            if upgrade_version == '':
                continue
            # print(f'DEBUG: Upgrade dep = {comp}@{version}')

            cmd = f"npm install {comp}@{upgrade_version} --package-lock-only >/dev/null 2>&1"
            # print(cmd)
            ret = os.system(cmd)

            if ret == 0:
                installed_packages.append([comp, upgrade_version])
                orig_deps_processed.append(dep)
            else:
                last_vulnerable_dirdeps.append(f"npmjs:{comp}/{upgrade_version}")

        if len(installed_packages) == 0:
            # print('No upgrades to test')
            continue
        print(f'Validating {len(installed_packages)} potential upgrades')

        pvurl, projname, vername, retval = bu.run_detect(detect_jar, detect_connection_opts, True)

        if retval == 3:
            # Policy violation returned
            rapid_scan_data, dep_dict, direct_deps_vuln, pm = bu.process_scan('upgrade-tests', bd, [], False, False)

            # print(f'MYDEBUG: Vuln direct deps = {direct_deps_vuln}')
            for vulndep in direct_deps_vuln:
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
