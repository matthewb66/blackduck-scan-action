# import argparse
import glob
# import hashlib
import json
import os
import sys
from bdscan import globals

from BlackDuckUtils import Utils
from BlackDuckUtils import NpmUtils
from BlackDuckUtils import MavenUtils
from BlackDuckUtils import NugetUtils


def get_blackduck_status(output_dir):
    bd_output_status_glob = max(glob.glob(output_dir + "/runs/*/status/status.json"), key=os.path.getmtime)
    if len(bd_output_status_glob) == 0:
        print("BD-Scan-Action: ERROR: Unable to find output scan files in: " + output_dir + "/runs/*/status/status.json")
        sys.exit(1)

    bd_output_status = bd_output_status_glob

    # print("INFO: Parsing Black Duck Scan output from " + bd_output_status)
    with open(bd_output_status) as f:
        output_status_data = json.load(f)

    detected_package_files = []
    found_detectors = 0
    for detector in output_status_data['detectors']:
        # Reverse order so that we get the priority from detect
        if detector['detectorType'] != 'GIT':
            found_detectors += 1
        for explanation in reversed(detector['explanations']):
            if str.startswith(explanation, "Found file: "):
                package_file = explanation[len("Found file: "):]
                if os.path.isfile(package_file):
                    detected_package_files.append(package_file)
                    globals.printdebug(f"DEBUG: Explanation: {explanation} File: {package_file}")

    if found_detectors == 0:
        print(f"BD-Scan-Action: WARN: No package manager scan identified (empty scan?) - Exiting")
        sys.exit(2)

    # Find project name and version to use in looking up baseline data
    project_baseline_name = output_status_data['projectName']
    project_baseline_version = output_status_data['projectVersion']

    return project_baseline_name, project_baseline_version, detected_package_files


def get_rapid_scan_results(output_dir, bd):
    # Parse the Rapid Scan output, assuming there is only one run in the directory
    filelist = glob.glob(output_dir + "/runs/*/scan/*.json")
    if len(filelist) <= 0:
        return None
    bd_rapid_output_file_glob = max(filelist, key=os.path.getmtime)
    if len(bd_rapid_output_file_glob) == 0:
        print("BD-Scan-Action: ERROR: Unable to find output scan files in: " + output_dir + "/runs/*/scan/*.json")
        return None

    bd_rapid_output_file = bd_rapid_output_file_glob
    # print("INFO: Parsing Black Duck Rapid Scan output from " + bd_rapid_output_file)
    with open(bd_rapid_output_file) as f:
        output_data = json.load(f)

    if len(output_data) <= 0 or '_meta' not in output_data[0] or 'href' not in output_data[0]['_meta']:
        return None

    developer_scan_url = output_data[0]['_meta']['href'] + "?limit=5000"
    globals.printdebug("DEBUG: Developer scan href: " + developer_scan_url)

    # Handle limited lifetime of developer runs gracefully
    try:
        rapid_scan_results = bd.get_json(developer_scan_url)
    except Exception as e:
        print(
            f"BD-Scan-Action: ERROR: Unable to fetch developer scan '{developer_scan_url}' \
- note that these are limited lifetime and this process must run immediately following the rapid scan")
        raise

    # TODO: Handle error if can't read file
    globals.printdebug("DEBUG: Developer scan data: " + json.dumps(rapid_scan_results, indent=4) + "\n")
    # print("DEBUG: Developer scan data: " + json.dumps(rapid_scan_results, indent=4) + "\n")

    return rapid_scan_results


def process_rapid_scan(rapid_scan_data, incremental, baseline_comp_cache, bdio_graph, bdio_projects, upgrade_indirect):
    allpoms = MavenUtils.find_allpomfiles()

    import networkx as nx
    pm = ''

    # Process all deps
    direct_deps_to_upgrade = {}
    dep_dict = {}
    for item in rapid_scan_data:
        # print(json.dumps(item, indent=4))
        # Loop through comps to determine what needs upgrading

        dep_vulnerable = False
        if len(item['policyViolationVulnerabilities']) > 0:
            dep_vulnerable = True

        globals.printdebug(f"DEBUG: Component: {item['componentIdentifier']}")
        globals.printdebug(item)

        comp_ns, comp_name, comp_version = Utils.parse_component_id(item['componentIdentifier'])

        # If comparing to baseline, look up in cache and continue if already exists
        if incremental and item['componentName'] in baseline_comp_cache:
            if (item['versionName'] in baseline_comp_cache[item['componentName']] and
                    baseline_comp_cache[item['componentName']][item['versionName']] == 1):
                globals.printdebug(f"DEBUG:   Skipping component {item['componentName']} \
version {item['versionName']} because it was already seen in baseline")
                continue
            else:
                globals.printdebug(f"DEBUG:   Including component {item['componentName']} \
version {item['versionName']} because it was not seen in baseline")

        # Track the root dependencies
        dependency_paths = []
        # direct_ancestors = dict()

        # Matching in the BDIO requires an http: prefix
        if comp_ns == "npmjs":
            http_name = NpmUtils.convert_dep_to_bdio(item['componentIdentifier'])
            if pm != '' and pm != 'npm':
                print(f"BD-Scan-Action: ERROR: Mixed package managers not supported")
                sys.exit(1)
            else:
                pm = 'npm'
        elif comp_ns == "maven":
            http_name = MavenUtils.convert_to_bdio(item['componentIdentifier'])
            if pm != '' and pm != 'maven':
                print(f"BD-Scan-Action: ERROR: Mixed package managers not supported")
                sys.exit(1)
            else:
                pm = 'maven'
        elif comp_ns == "nuget":
            http_name = NugetUtils.convert_to_bdio(item['componentIdentifier'])
            if pm != '' and pm != 'nuget':
                print(f"BD-Scan-Action: ERROR: Mixed package managers not supported")
                sys.exit(1)
            else:
                pm = 'nuget'
        else:
            print(f"BD-Scan-Action: ERROR: Domain '{comp_ns}' not supported yet")
            sys.exit(1)

        dep_dict[item['componentIdentifier']] = {
            'compname': comp_name,
            'compversion': comp_version,
            'compns': comp_ns,
            'directparents': [],
        }
        globals.printdebug(f"DEBUG: Looking for {http_name}")
        ancs = nx.ancestors(bdio_graph, http_name)
        ancs_list = list(ancs)

        # Process the paths
        dep_dict[item['componentIdentifier']]['deptype'] = 'Indirect'
        for proj in bdio_projects:
            dep_paths = nx.all_simple_paths(bdio_graph, source=proj, target=http_name)
            globals.printdebug(f"DEBUG: Paths to '{http_name}'")
            for path in dep_paths:
                # First generate a string for easy output and reading
                # path_modified.pop(0)

                path_mod = []
                i = 0
                projfile = ''
                for p in path:
                    if not p.endswith(f'/{pm}') and not p.startswith('http:detect/'):
                        path_mod.append(p)
                    elif p.endswith('/nuget'):
                        projfile = NugetUtils.get_projfile(p)
                    elif p.endswith('/maven'):
                        projfile = MavenUtils.get_projfile(p, allpoms)
                    i += 1

                direct_dep = Utils.normalise_dep(pm, path_mod[0])

                if projfile != '':
                    if comp_ns == 'maven':
                        # For Maven - if this is a sub-bom, then need to check if the direct_dep exists there
                        outfile, linenum = Utils.find_comp_in_projfiles([projfile], direct_dep)
                        if linenum <= 0:
                            # direct component does not exists in this pomfile - skip this path
                            continue
                else:
                    for file in globals.detected_package_files:
                        outfile, linenum = Utils.find_comp_in_projfiles([file], direct_dep)
                        if linenum > 0:
                            projfile = outfile
                            break

                # pathstr = " -> ".join(path_mod)
                # dependency_paths.append(pathstr)
                if len(path_mod) == 1 and path_mod[0] == http_name:
                    # This is actually a direct dependency
                    dep_dict[item['componentIdentifier']]['deptype'] = 'Direct'
                    dep_dict[item['componentIdentifier']]['directparents'] = []
                else:
                    dep_dict[item['componentIdentifier']]['directparents'].append(direct_dep)

                # Then log the direct dependencies directly
                childdep = Utils.normalise_dep(pm, item['componentIdentifier'])
                if direct_dep != '' and dep_vulnerable:
                    if direct_dep not in direct_deps_to_upgrade.keys():
                        direct_deps_to_upgrade[direct_dep] = [projfile]
                    # elif childdep not in direct_deps_to_upgrade[direct_dep]['children']:
                    #     direct_deps_to_upgrade[direct_dep]['children'].append(childdep)
                    #     direct_deps_to_upgrade[direct_dep]['projfiles'].append(projfile)
                    elif projfile not in direct_deps_to_upgrade[direct_dep]:
                        # direct_deps_to_upgrade[direct_dep]['children'].append(childdep)
                        direct_deps_to_upgrade[direct_dep].append(projfile)
            # dep_dict[item['componentIdentifier']]['paths'] = dependency_paths

    # direct_list = []
    # # Check for duplicate direct and indirect deps
    # for dir in direct_deps_to_upgrade.keys():
    #     item = direct_deps_to_upgrade[dir]
    #     if dir not in direct_list:
    #         if dir == item or item not in direct_deps_to_upgrade.keys():
    #             direct_list.append(dir)

    # return dep_dict, direct_list, pm
    globals.printdebug(f"DEBUG: VULNERABLE DIRECT DEPENDENCIES:\n{direct_deps_to_upgrade.keys()}")
    return dep_dict, direct_deps_to_upgrade, pm
