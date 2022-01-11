import json
import sys
import hashlib
import os
from operator import itemgetter

from blackduck import Client

from BlackDuckUtils import BlackDuckOutput as bo
from BlackDuckUtils import Utils as bu
# from BlackDuckUtils import bdio as bdio
from BlackDuckUtils import asyncdata as asyncdata

from bdscan import globals
from bdscan import github_workflow


def process_bd_scan(output):
    project_baseline_name, project_baseline_version, globals.detected_package_files = \
        bo.get_blackduck_status(output)

    # Look up baseline data
    pvurl = bu.get_projver(globals.bd, project_baseline_name, project_baseline_version)
    globals.baseline_comp_cache = dict()
    if globals.args.incremental_results:
        if pvurl == '':
            print(f"BD-Scan-Action: WARN: Unable to find project '{project_baseline_name}' \
version '{project_baseline_version}' - will not present incremental results")
        else:
            globals.printdebug(f"DEBUG: Project Version URL: {pvurl}")
            baseline_comps = bu.get_comps(globals.bd, pvurl)
            # if (globals.debug): print(f"DEBUG: Baseline components=" + json.dumps(baseline_comps, indent=4))
            # sys.exit(1)
            # Can't cache the component Id / external id very easily here as it's not top-level,
            # and may have multiple origins
            for comp in baseline_comps:
                if not comp['componentName'] in globals.baseline_comp_cache:
                    globals.baseline_comp_cache[comp['componentName']] = dict()
                # if (baseline_comp_cache[comp['componentName']] == None): baseline_comp_cache[comp['componentName']]
                # = dict()
                globals.baseline_comp_cache[comp['componentName']][comp['componentVersionName']] = 1
                # baseline_comp_cache[comp['componentName']] = comp['componentVersionName']
            globals.printdebug(f"DEBUG: Baseline component cache=" + json.dumps(globals.baseline_comp_cache, indent=4))
            globals.printdebug(f"DEBUG: Generated baseline component cache")

    # bdio_graph, bdio_projects = bdio.get_bdio_dependency_graph(globals.args.output)
    #
    # if len(bdio_projects) == 0:
    #     print("ERROR: Unable to find base project in BDIO file")
    #     sys.exit(1)

    rapid_scan_data, dep_dict, direct_deps_to_upgrade, pm = bu.process_scan(
        globals.args.output, globals.bd, globals.baseline_comp_cache,
        globals.args.incremental_results, globals.args.upgrade_indirect)

    return rapid_scan_data, dep_dict, direct_deps_to_upgrade, pm


def unique(list1):
    unique_list = []
    for x in list1:
        # check if exists in unique_list or not
        if x not in unique_list:
            unique_list.append(x)
    return unique_list


def create_scan_outputs(rapid_scan_data, upgrade_dict, dep_dict, direct_deps_to_upgrade):
    def vuln_color(value):
        if value > 9:
            return f'<span style="color:DarkRed">{str(value)}</span>'
        elif value > 7:
            return f'<span style="color:Red">{str(value)}</span>'
        elif value > 5:
            return f'<span style="color:Orange">{str(value)}</span>'
        else:
            return f'{str(value)}'

    def count_vulns(parentid, childid, existing_vulns):
        if parentid != '':
            parent_ns, parent_name, parent_ver = bu.parse_component_id(parentid)
        else:
            parent_ns = ''
            parent_name = ''
            parent_ver = ''

        child_ns, child_name, child_ver = bu.parse_component_id(childid)
        if globals.args.incremental_results and child_name in globals.baseline_comp_cache:
            if (child_ver in globals.baseline_comp_cache[child_name] and
                    globals.baseline_comp_cache[child_name][child_ver] == 1):
                globals.printdebug(f"DEBUG:   Skipping child component {child_name} \
                version {child_ver} because it was already seen in baseline")
                return existing_vulns, 0, 0, []
            else:
                globals.printdebug(f"DEBUG:   Including child component {child_name} \
                version {child_ver} because it was not seen in baseline")

        vuln_count = 0
        max_vuln_severity = 0
        cvulns_list = []

        for rscanitem in rapid_scan_data['items']:
            if rscanitem['componentIdentifier'] == childid:
                for vuln in rscanitem['policyViolationVulnerabilities']:
                    if vuln['name'] in existing_vulns:
                        continue
                    existing_vulns.append(vuln['name'])
                    vuln_count += 1
                    # print(f"vuln={vuln}")
                    if max_vuln_severity < vuln['overallScore']:
                        max_vuln_severity = vuln['overallScore']

                    desc = vuln['description'].replace('\n', ' ')[:200]
                    if len(desc) > 200:
                        desc += ' ...'
                    name = f"{vuln['name']}"
                    link = f"{globals.args.url}/api/vulnerabilities/{name}/overview"
                    vulnname = f'<a href="{link}" target="_blank">{name}</a>'

                    cvulns_list.append(
                        [
                            f"{parent_name}/{parent_ver}",
                            f"{child_name}/{child_ver}",
                            vulnname,
                            vuln['overallScore'],
                            vuln['violatingPolicies'][0]['policyName'],
                            desc,
                            child_ver,
                        ]
                    )
                break

        # Sort the table
        cvulns_list = sorted(cvulns_list, key=itemgetter(3), reverse=True)

        # add colours to vuln scores
        cvulns_table = []
        for crow in cvulns_list:
            vscore = vuln_color(crow[3])
            # | Parent | Component | Vulnerability | Severity |  Policy | Description | Current Ver |
            cvulns_table.append(f"| {crow[0]} | {crow[1]} | {crow[2]} | {vscore} | {crow[4]} | {crow[5]} | {crow[6]} |")

        return existing_vulns, vuln_count, max_vuln_severity, cvulns_table
    ##### End of count_vulns()

    globals.printdebug(f"DEBUG: Entering create_scan_outputs({rapid_scan_data},\n{upgrade_dict},\n{dep_dict}")

    md_directdeps_header = [
        "",
        "## Direct Dependencies with vulnerabilities (in direct or transitive children):",
        "",
        f"| Direct Dependency | Num Direct Vulns | Max Direct Vuln Severity | Num Indirect Vulns "
        f"| Max Indirect Vuln Severity | Upgrade to |",
        "| --- | --- | --- | --- | --- | --- |"
    ]
    md_vulns_header = [
        "",
        "| Parent | Child Component | Vulnerability | Score |  Policy | Description | Current Ver |",
        "| --- | --- | --- | --- | --- | --- | --- |"
    ]
    md_directdeps_list = []

    md_all_vulns_table = md_vulns_header[:]

    # for item in rapid_scan_data['items']:
    for compid in direct_deps_to_upgrade.keys():
        # compid = item['componentIdentifier']

        comp_ns, comp_name, comp_version = bu.parse_component_id(compid)

        if compid in upgrade_dict:
            upgrade_ver = upgrade_dict[compid]
        else:
            upgrade_ver = None

        # If package file for this direct dep is blank, find from the detect-returned package files
        pkgfiles = []
        pkglines = []
        for projfile in unique(direct_deps_to_upgrade[compid]['projfiles']):
            if projfile == '':
                package_file, package_line = bu.detect_package_file(globals.detected_package_files, compid)
            else:
                package_file, package_line = bu.detect_package_file(projfile, compid)
            if package_file != 'Unknown' and package_line > 0:
                pkgfiles.append(package_file)
                pkglines.append(package_line)

        children = []
        for alldep in dep_dict.keys():
            if compid in dep_dict[alldep]['directparents']:
                children.append(alldep)

        # print(f"parent={comp_name}/{comp_version} - children={children}")

        md_comp_vulns_table = md_vulns_header[:]
        dir_vulns, dir_vuln_count, dir_max_sev, md_comp_vtable = count_vulns('', compid, [])
        md_all_vulns_table.extend(md_comp_vtable)
        md_comp_vulns_table.extend(md_comp_vtable)

        children_max_sev = 0
        children_num_vulns = 0
        children_string = ''

        for childid in children:
            # Find child in rapidscan data
            child_ns, child_name, child_ver = bu.parse_component_id(childid)
            if childid != compid:
                children_string += f"{child_name}/{child_ver},"
            else:
                continue

            md_cvulns_table = []
            dir_vulns, cvuln_count, cmax_sev, md_cvulns_table = count_vulns(compid, childid, dir_vulns)
            md_comp_vulns_table.extend(md_cvulns_table)
            md_all_vulns_table.extend(md_cvulns_table)

            if cmax_sev > children_max_sev:
                children_max_sev = cmax_sev
            children_num_vulns += cvuln_count

        if upgrade_ver is None:
            uver = 'N/A'
        else:
            uver = upgrade_ver
        # pfile = bu.remove_cwd_from_filename(package_file)

        # | Direct Dependency | Max Vuln Severity | No. of Vulns | Upgrade to | File |
        md_directdeps_list.append(
            [
                f"{comp_name}/{comp_version}",
                dir_vuln_count,
                dir_max_sev,
                children_num_vulns,
                children_max_sev,
                uver,
            ]
        )

        if dir_vuln_count > 0 and children_num_vulns > 0:
            shorttext = f"The direct dependency {comp_name}/{comp_version} has {dir_vuln_count} vulnerabilities (max " \
                        f"score {dir_max_sev}) and {children_num_vulns} vulnerabilities in child dependencies (max " \
                        f"score {children_max_sev})."
            longtext_md = shorttext + "\n\n" + '\n'.join(md_comp_vulns_table) + '\n'
            longtext = f"{shorttext}\n\nList of direct and indirect vulnerabilities:\n{','.join(dir_vulns)}"
        elif dir_vuln_count > 0 and children_num_vulns == 0:
            shorttext = f"The direct dependency {comp_name}/{comp_version} has {dir_vuln_count} vulnerabilities (max " \
                        f"score {dir_max_sev})."
            longtext_md = shorttext + "\n\n" + '\n'.join(md_comp_vulns_table) + '\n'
            longtext = f"{shorttext}\n\nList of direct vulnerabilities:\n{','.join(dir_vulns)}"
        elif children_num_vulns > 0:
            shorttext = f"The direct dependency {comp_name}/{comp_version} has {children_num_vulns} vulnerabilities " \
                        f"in child dependencies (max score {children_max_sev})."
            longtext_md = shorttext + "\n\n" + '\n'.join(md_comp_vulns_table) + '\n'
            longtext = f"{shorttext}\n\nList of indirect vulnerabilities:\n{','.join(dir_vulns)}"
        else:
            shorttext = ''
            longtext_md = ''
            longtext = ''

        fix_pr_node = dict()
        if upgrade_ver is not None:
            fix_pr_node = {
                'componentName': comp_name,
                'versionFrom': comp_version,
                'versionTo': upgrade_ver,
                'ns': comp_ns,
                'filename': bu.remove_cwd_from_filename(package_file),
                'comments': [f"## Dependency {comp_name}/{comp_version}\n{shorttext}"],
                'comments_markdown': [longtext_md],
                'comments_markdown_footer': ''
            }

        globals.comment_on_pr_comments.append(f"## {comp_name}/{comp_version}\n{longtext_md}")

        result = {
            'ruleId': comp_name,
            'message': {
                'text': shorttext
            },
            'locations': [
                {
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': bu.remove_cwd_from_filename(package_file),
                        },
                        'region': {
                            'startLine': package_line,
                        }
                    }
                }
            ],
            'partialFingerprints': {
                'primaryLocationLineHash': hashlib.sha224(b"{compid}").hexdigest(),
            }
        }
        globals.results.append(result)

        if children_max_sev >= 7 or dir_max_sev >= 7:
            level = "error"
        elif children_max_sev >= 4 or dir_max_sev >= 4:
            level = "warning"
        else:
            level = "note"

        if upgrade_ver is not None:
            uhelp = f"{longtext_md}\n\nRecommended to upgrade to version {upgrade_ver}.\n\n"
        else:
            uhelp = f"{longtext_md}\n\nNo upgrade available at this time.\n\n"

        tool_rule = {
            'id': comp_name,
            'shortDescription': {
                'text': shorttext,
            },
            'fullDescription': {
                'text': longtext,
            },
            'help': {
                'text': '',
                'markdown': uhelp,
            },
            'defaultConfiguration': {
                'level': level,
            },
            'properties': {
                'tags': ["security"],
                'security-severity': str(dir_max_sev)
            }
        }

        globals.tool_rules.append(tool_rule)

        if upgrade_ver is not None:
            a_comp = compid.replace(':', '@').replace('/', '@').split('@')
            globals.fix_pr_data[f"{a_comp[1]}@{a_comp[2]}"] = fix_pr_node

    md_directdeps_list = sorted(md_directdeps_list, key=itemgetter(2), reverse=True)
    md_directdeps_list = sorted(md_directdeps_list, key=itemgetter(4), reverse=True)

    md_directdeps_table = md_directdeps_header
    for crow in md_directdeps_list:
        # | Direct Dependency | Num Direct Vulns | Max Direct Vuln Severity | Num Indirect Vulns
        # | Max Indirect Vuln Severity | Upgrade to |",
        md_directdeps_table.append(f"| {crow[0]} | {crow[1]} | {vuln_color(crow[2])} | {crow[3]} "
                                   f"| {vuln_color(crow[4])} | {crow[5]} |")

    globals.comment_on_pr_comments = md_directdeps_table + ['\n'] + globals.comment_on_pr_comments


def test_upgrades(upgrade_dict, deplist, pm):
    bd_connect_args = [
        f'--blackduck.url={globals.args.url}',
        f'--blackduck.api.token={globals.args.token}',
    ]
    if globals.args.trustcert:
        bd_connect_args.append(f'--blackduck.trust.cert=true')
    # print(deplist)
    # good_upgrades_dict = bu.attempt_indirect_upgrade(
    #     pm, deplist, upgrade_dict, globals.detect_jar, bd_connect_args, globals.bd)
    good_upgrades_dict = bu.attempt_indirect_upgrade(
        pm, deplist, upgrade_dict, globals.detect_jar, bd_connect_args, globals.bd, globals.args.upgrade_indirect,
        globals.args.upgrade_major)
    return good_upgrades_dict


def write_sarif(sarif_file):
    code_security_scan_report = {
        '$schema': "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        'version': "2.1.0",
        'runs': [
            {
                'tool': {
                    'driver': {
                        'name': 'Synopsys Black Duck',
                        'organization': 'Synopsys',
                        'version': globals.scan_utility_version,
                        'rules': globals.tool_rules,
                    }
                },
                'results': globals.results,
            }
        ],
    }

    globals.printdebug("DEBUG: SARIF Data structure=" + json.dumps(code_security_scan_report, indent=4))
    try:
        with open(sarif_file, "w") as fp:
            json.dump(code_security_scan_report, fp, indent=4)
    except Exception as e:
        print(f"BD-Scan-Action: ERROR: Unable to write to SARIF output file '{sarif_file} - '" + str(e))
        sys.exit(1)


def main_process(output, runargs):
    # Run DETECT
    pvurl, projname, vername, detect_return_code = bu.run_detect(globals.detect_jar, runargs, True)
    if detect_return_code > 0 and detect_return_code != 3:
        print(f"BD-Scan-Action: ERROR: Black Duck detect returned exit code {detect_return_code}")
        sys.exit(detect_return_code)

    if globals.args.mode == "intelligent":
        # Stop here
        sys.exit(0)

    # Todo - Add proxy support
    globals.bd = Client(token=globals.args.token,
                        base_url=globals.args.url,
                        verify=globals.args.trustcert,
                        timeout=300)

    if globals.bd is None:
        print('BD-Scan-Action: ERROR: Unable to connect to Black Duck server - check credentials')

    # Process the Rapid scan
    print('\nBD-Scan-Action: Processing scan data ...')
    rapid_scan_data, dep_dict, direct_deps_to_upgrade, pm = process_bd_scan(output)

    if rapid_scan_data is None:
        print('BD-Scan-Action: INFO: No policy violations found - Ending gracefully')
        sys.exit(0)

    if globals.args.upgrade_indirect:
        # check for indirect upgrades
        #
        # Get component data via async calls
        guidance_dict, version_dict, origin_dict = asyncdata.get_data_async(direct_deps_to_upgrade, globals.bd,
                                                                            globals.args.trustcert)

        # Work out possible upgrades
        globals.printdebug('BD-Scan-Action: Identifying upgrades ...')
        upgrade_dict = {}
        globals.printdebug('DEBUG: DIRECT DEPS TO UPGRADE')
        globals.printdebug(json.dumps(direct_deps_to_upgrade, indent=4))
        globals.printdebug('DEBUG: VERSION DICT')
        globals.printdebug(json.dumps(version_dict, indent=4))
        globals.printdebug('DEBUG: GUIDANCE DICT')
        globals.printdebug(json.dumps(guidance_dict, indent=4))
        for dep in direct_deps_to_upgrade.keys():
            globals.printdebug(f'DEBUG: Checking {dep}')
            if dep in version_dict.keys() and dep in guidance_dict.keys():
                upgrade_dict[dep] = bu.find_upgrade_versions(dep, version_dict[dep], origin_dict, guidance_dict[dep],
                                                             globals.args.upgrade_major)
                globals.printdebug(f'DEBUG: find_upgrade_versions() returned {upgrade_dict[dep]}')

        # Test upgrades using Detect Rapid scans
        good_upgrades = test_upgrades(upgrade_dict, list(direct_deps_to_upgrade.keys()), pm)
    else:
        good_upgrades = {}

    # Process data
    create_scan_outputs(rapid_scan_data, good_upgrades, dep_dict, direct_deps_to_upgrade)

    if globals.args.sarif is not None and globals.args.sarif != '':
        print(f"BD-Scan-Action: Writing sarif output file '{globals.args.sarif}' ...")
        write_sarif(globals.args.sarif)

    globals.github_token = os.getenv("GITHUB_TOKEN")
    globals.github_repo = os.getenv("GITHUB_REPOSITORY")
    globals.github_ref = os.getenv("GITHUB_REF")
    globals.printdebug(f'GITHUB_REF={globals.github_ref}')
    globals.github_api_url = os.getenv("GITHUB_API_URL")
    globals.github_sha = os.getenv("GITHUB_SHA")
    globals.printdebug(f'GITHUB_SHA={globals.github_sha}')

    # Optionally generate Fix PR
    if globals.args.fix_pr:
        if len(globals.fix_pr_data.values()) > 0:
            if github_workflow.github_fix_pr():
                github_workflow.github_set_commit_status(True)
                print('BD-Scan-Action: Created fix pull request')
            else:
                print('ERROR: Unable to create fix pull request')
                sys.exit(1)
        else:
            print('BD-Scan-Action: No ugrades available for Fix PR - skipping')

    # Optionally comment on the pull request this is for
    if globals.args.comment_on_pr:
        if len(globals.comment_on_pr_comments) > 0:
            if github_workflow.github_pr_comment():
                github_workflow.github_set_commit_status(True)
                print('BD-Scan-Action: Created comment on existing pull request')
            else:
                print('ERROR: Unable to create comment on existing pull request')
                sys.exit(1)
        else:
            print('BD-Scan-Action: No ugrades available for Comment on PR - skipping')

    print('Done - SUCCESS')
    sys.exit(0)
