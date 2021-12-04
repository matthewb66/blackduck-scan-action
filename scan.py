# import argparse
# import glob
# import hashlib
import json
# import os
# import random
# import shutil
import sys
# import zipfile
import aiohttp
import asyncio

from BlackDuckUtils import BlackDuckOutput as bo
from BlackDuckUtils import Utils as bu
from BlackDuckUtils import bdio as bdio

# from blackduck import Client
import globals
import github_workflow


# TODO Better to read BD API Token from environment variable
# bd_apitoken = os.getenv("BLACKDUCK_TOKEN")
# if (bd_apitoken == None or bd_apitoken == ""):
#    print("ERROR: Please set BLACKDUCK_TOKEN in environment before running")
#    sys.exit(1)


async def async_main(compidlist, bd):
    token = bd.session.auth.bearer_token

    async with aiohttp.ClientSession() as session:
        compdata_tasks = []

        for compid in compidlist:
            compdata_task = asyncio.ensure_future(async_get_compdata(session, bd.base_url, compid, token))
            compdata_tasks.append(compdata_task)

        print('Getting componentids ... ')
        # print(f'compidlist: {compidlist}')
        all_compdata = dict(await asyncio.gather(*compdata_tasks))
        await asyncio.sleep(0.25)

    async with aiohttp.ClientSession() as session:
        upgradeguidance_tasks = []
        versions_tasks = []

        for compid in compidlist:
            upgradeguidance_task = asyncio.ensure_future(async_get_guidance(session, compid, all_compdata, token))
            upgradeguidance_tasks.append(upgradeguidance_task)

            versions_task = asyncio.ensure_future(async_get_versions(session, compid, all_compdata, token))
            versions_tasks.append(versions_task)

        print('Getting component versions & upgrade guidance ... ')
        all_upgradeguidances = dict(await asyncio.gather(*upgradeguidance_tasks))
        all_versions = dict(await asyncio.gather(*versions_tasks))
        await asyncio.sleep(0.25)

    async with aiohttp.ClientSession() as session:
        origins_tasks = []

        for compid in compidlist:
            tempcompid = compid.replace(':', '@').replace('/', '@')
            arr = tempcompid.split('@')
            if compid not in all_versions.keys():
                continue
            # print(f'DEBUG {compid} - {len(all_versions[compid])}')
            for vers, versurl in all_versions[compid]:
                if vers == arr[2]:
                    break
                origins_task = asyncio.ensure_future(async_get_origins(session, compid, all_compdata,
                                                                       vers, versurl, token))
                origins_tasks.append(origins_task)

        print('Getting version origins ... ')
        all_origins = dict(await asyncio.gather(*origins_tasks))
        await asyncio.sleep(0.25)

    # return all_upgradeguidances, all_versions
    return all_upgradeguidances, all_versions, all_origins


async def async_get_compdata(session, baseurl, compid, token):
    # if 'componentIdentifier' not in comp:
    #     return None, None
    #
    if not globals.args.trustcert:
        ssl = False
    else:
        ssl = None

    headers = {
        'accept': "application/vnd.blackducksoftware.component-detail-4+json",
        'Authorization': f'Bearer {token}',
    }

    params = {
        # 'q': [comp['componentIdentifier']],
        'q': [compid],
    }
    # search_results = bd.get_items('/api/components', params=params)
    async with session.get(baseurl + '/api/components', headers=headers, params=params, ssl=ssl) as resp:
        found_comps = await resp.json()

    # print('----')
    # print(baseurl + '/api/components?q=' + compid)
    # print(found_comps)
    if 'items' not in found_comps or len(found_comps['items']) != 1:
        return None, None

    found = found_comps['items'][0]

    # return comp['componentIdentifier'], [found['variant'] + '/upgrade-guidance', found['component'] + '/versions']
    return compid, [found['variant'] + '/upgrade-guidance', found['component'] + '/versions']


async def async_get_versions(session, compid, compdata, token):
    if compid in compdata:
        gurl = compdata[compid][1]
    else:
        return None, None

    if not globals.args.trustcert:
        ssl = False
    else:
        ssl = None

    # print(f'GETTING VERSION: {compid}')
    headers = {
        'accept': "application/vnd.blackducksoftware.component-detail-4+json",
        'Authorization': f'Bearer {token}',
    }

    params = {
        'limit': 500,
        'sort': 'releasedOn'
    }

    async with session.get(gurl, headers=headers, params=params, ssl=ssl) as resp:
        res = await resp.json()

    versions_list = []
    for version in res['items'][::-1]:
        item = [version['versionName'], version['_meta']['href']]
        versions_list.append(item)

    # print(comp['componentName'])
    # print(gurl)
    # print(versions_list)
    #
    return compid, versions_list


async def async_get_guidance(session, compid, compdata, token):
    if not globals.args.trustcert:
        ssl = False
    else:
        ssl = None

    headers = {
        'accept': "application/vnd.blackducksoftware.component-detail-5+json",
        'Authorization': f'Bearer {token}',
    }
    # if 'componentIdentifier' in comp and comp['componentIdentifier'] in compdata:
    #     gurl = compdata[comp['componentIdentifier']][0]
    # else:
    #     return None, None
    if compid in compdata.keys():
        gurl = compdata[compid][0]
    else:
        return None, None

    # print(gurl)
    async with session.get(gurl, headers=headers, ssl=ssl) as resp:
        component_upgrade_data = await resp.json()

    globals.printdebug(component_upgrade_data)
    if "longTerm" in component_upgrade_data.keys():
        longTerm = component_upgrade_data['longTerm']['versionName']
    else:
        longTerm = ''

    if "shortTerm" in component_upgrade_data.keys():
        shortTerm = component_upgrade_data['shortTerm']['versionName']
    else:
        shortTerm = ''
    # print(f"Comp = {comp['componentName']}/{comp['versionName']} - Short = {shortTerm} Long = {longTerm}")

    if shortTerm == longTerm:
        longTerm = ''
    return compid, [shortTerm, longTerm]


async def async_get_origins(session, compid, compdata, ver, verurl, token):
    if not globals.args.trustcert:
        ssl = False
    else:
        ssl = None

    headers = {
        'accept': "application/vnd.blackducksoftware.component-detail-5+json",
        'Authorization': f'Bearer {token}',
    }
    # if 'componentIdentifier' in comp and comp['componentIdentifier'] in compdata:
    #     gurl = compdata[comp['componentIdentifier']][0]
    # else:
    #     return None, None

    async with session.get(verurl + '/origins', headers=headers, ssl=ssl) as resp:
        origins = await resp.json()

    # print('get_origins:')
    # print(verurl)
    # print(json.dumps(origins, indent=4))

    return compid, origins['items']


def find_upgrade_versions(dirdep, versions_list, origin_dict, guidance_upgrades):
    # Clean & check the dependency string
    moddep = dirdep.replace(':', '@').replace('/', '@')
    arr = moddep.split('@')
    if len(arr) != 3:
        return
    origin = arr[0]
    component_name = arr[1]
    current_version = arr[2]
    n_ver = bu.normalise_version(current_version)
    if n_ver is None:
        return

    future_vers = []
    if dirdep in origin_dict.keys():
        #
        # Find future versions from the same origin
        for o_ver in origin_dict[dirdep]:
            if 'originName' in o_ver and o_ver['originName'] == origin:
                # Find this version in versions_list
                for v_ver, v_url in versions_list:
                    if v_ver == o_ver['versionName']:
                        future_vers.append([v_ver, v_url])
                        break
    # print(f"Future versions within same origin = {len(future_vers)}")

    ver_within_major_range = ''
    ver_next_major_range = ''
    ver_latest = ''
    for version, vurl in future_vers:
        new_ver = bu.normalise_version(version)
        if new_ver is None:
            continue

        if ver_within_major_range == '' and new_ver.major == n_ver.major and new_ver.minor > n_ver.minor and \
                n_ver != new_ver:
            ver_within_major_range = version
        elif ver_next_major_range == '' and new_ver.major == n_ver.major + 1:
            ver_next_major_range = version
        elif ver_latest == '' and new_ver != n_ver:
            ver_latest = version

    upgrade_versions = []
    for str in [ver_within_major_range, ver_next_major_range, ver_latest]:
        if str != '':
            upgrade_versions.append(str)

    return upgrade_versions


def process_upgrades(deplist, version_dict, guidance_dict, origin_dict):
    #
    # Check if BD upgrade guidance exists for this component
    upgrade_dict = {}
    for dep in deplist:
        guidance_upgrades = []
        for ind in [0, 1]:
            ver = guidance_dict[dep][ind]
            if ver != '':
                tempver = bu.normalise_version(ver)
                if tempver is not None:
                    guidance_upgrades.append(ver)

        if len(guidance_upgrades) > 0:
            # print(f'BD UPGRADE GUIDANCE for {dep} - {guidance_upgrades}')
            upgrade_dict[dep] = guidance_upgrades
        else:
            upgrade_dict[dep] = find_upgrade_versions(dep, version_dict[dep], origin_dict, guidance_upgrades)
    return upgrade_dict


def test_upgrades(upgrade_dict, deplist, pm):
    bd_connect_args = [
        f'--blackduck.url={globals.args.url}',
        f'--blackduck.api.token={globals.args.token}',
    ]
    if globals.args.trustcert:
        bd_connect_args.append(f'--blackduck.trust.cert=true')
    # print(deplist)
    upgrade_count, good_upgrades_dict = bu.attempt_indirect_upgrade(pm, deplist, upgrade_dict, globals.detect_jar, bd_connect_args,
                                                globals.bd)
    return upgrade_count, good_upgrades_dict


def write_sarif():
    # Prepare SARIF output structures
    run = dict()
    run['results'] = globals.results
    runs = [run]

    tool = dict()
    driver = dict()
    driver['name'] = "Synopsys Black Duck"
    driver['organization'] = "Synopsys"
    driver['rules'] = globals.tool_rules
    tool['driver'] = driver
    run['tool'] = tool

    code_security_scan_report = dict()
    code_security_scan_report['runs'] = runs
    code_security_scan_report['$schema'] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    code_security_scan_report['version'] = "2.1.0"
    code_security_scan_report['runs'] = runs

    globals.printdebug("DEBUG: SARIF Data structure=" + json.dumps(code_security_scan_report, indent=4))
    try:
        with open(globals.args.sarif, "w") as fp:
            json.dump(code_security_scan_report, fp, indent=4)
    except:
        print(f"ERROR: Unable to write to SARIF output file '{globals.args.sarif}'")
        sys.exit(1)


def process_bd_scan():
    project_baseline_name, project_baseline_version, globals.detected_package_files = \
        bo.get_blackduck_status(globals.args.output)

    # print(f"INFO: Running for project '{project_baseline_name}' version '{project_baseline_version}'")

    # Look up baseline data
    pvurl = bu.get_projver(globals.bd, project_baseline_name, project_baseline_version)
    baseline_comp_cache = dict()
    if globals.args.incremental_results:
        if pvurl == '':
            print(f"WARN: Unable to find project '{project_baseline_name}' \
version '{project_baseline_version}' - will not present incremental results")
        else:
            globals.printdebug(f"DEBUG: Project Version URL: {pvurl}")
            baseline_comps = bu.get_comps(globals.bd, pvurl)
            # if (globals.debug): print(f"DEBUG: Baseline components=" + json.dumps(baseline_comps, indent=4))
            # sys.exit(1)
            # Can't cache the component Id / external id very easily here as it's not top-level,
            # and may have multiple origins
            for comp in baseline_comps:
                if not comp['componentName'] in baseline_comp_cache:
                    baseline_comp_cache[comp['componentName']] = dict()
                # if (baseline_comp_cache[comp['componentName']] == None): baseline_comp_cache[comp['componentName']] = dict()
                baseline_comp_cache[comp['componentName']][comp['componentVersionName']] = 1
                # baseline_comp_cache[comp['componentName']] = comp['componentVersionName']
            globals.printdebug(f"DEBUG: Baseline component cache=" + json.dumps(baseline_comp_cache, indent=4))
            globals.printdebug(f"DEBUG: Generated baseline component cache")

    bdio_graph, bdio_projects = bdio.get_bdio_dependency_graph(globals.args.output)

    if len(bdio_projects) == 0:
        print("ERROR: Unable to find base project in BDIO file")
        sys.exit(1)

    rapid_scan_data, dep_dict, direct_deps_to_upgrade, pm = bu.process_scan(
        globals.args.output, globals.bd, baseline_comp_cache,
        globals.args.incremental_results, globals.args.upgrade_indirect)

    return rapid_scan_data, dep_dict, direct_deps_to_upgrade, pm


def create_scan_outputs(rapid_scan_data, upgrade_dict, dep_dict):
    for compid in upgrade_dict.keys():
        # Loop the list of direct deps
        upgrades_list = upgrade_dict[compid]
        if len(upgrades_list) > 0:
            upgrade_ver = upgrades_list[0]
        else:
            upgrade_ver = None

        package_file, package_line = bu.detect_package_file(globals.detected_package_files, compid)

        ns, name, ver = bu.parse_component_id(compid)
        fix_pr_node = dict()
        if upgrade_ver is not None:
            fix_pr_node['componentName'] = name
            fix_pr_node['versionFrom'] = ver
            fix_pr_node['versionTo'] = upgrade_ver
            fix_pr_node['ns'] = ns
            fix_pr_node['filename'] = bu.remove_cwd_from_filename(package_file)
            fix_pr_node['comments'] = []
            fix_pr_node['comments_markdown'] = ["| Child Component | ID | Severity | Description | Vulnerable version \
| Upgrade to |", "| --- | --- | --- | --- | --- |"]
            fix_pr_node['comments_markdown_footer'] = ""

        children = []
        for alldep in dep_dict.keys():
            if compid in dep_dict[alldep]['directparents']:
                children.append(alldep)

        for child in children:
            # Find child in rapidscan data
            child_ns, child_name, child_ver = bu.parse_component_id(child)
            for rscanitem in rapid_scan_data['items']:
                if rscanitem['componentIdentifier'] == child:
                    for vuln in rscanitem['policyViolationVulnerabilities']:
                        message_markdown_footer = ''
                        if upgrade_ver is not None:
                            message = f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* Recommended to upgrade to version {upgrade_ver}."
                            message_markdown = f"| {vuln['name']} | {vuln['vulnSeverity']} | {vuln['description']} | {child_ver} | {upgrade_ver} | "
                            comment_on_pr = f"| {vuln['name']} | {child} | {vuln['name']} |  {vuln['vulnSeverity']} | {vuln['violatingPolicies'][0]['policyName']} | {vuln['description']} | {child_ver} | {upgrade_ver} |"
                        else:
                            message = f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* No upgrade available at this time."
                            message_markdown = f"| {vuln['name']} | {vuln['vulnSeverity']} | {vuln['description']} | {child_ver} | {upgrade_ver} | "
                            comment_on_pr = f"| {vuln['name']} | {child} | {vuln['name']} | {vuln['vulnSeverity']} | {vuln['violatingPolicies'][0]['policyName']} | {vuln['description']} | {child_ver} | N/A |"
        #
        #     if dep_dict[compid['componentIdentifier']]['deptype'] == "Direct":
                        message = message + f"Fix in package file '{bu.remove_cwd_from_filename(package_file)}'"
                        message_markdown_footer = f"**Fix in package file '{bu.remove_cwd_from_filename(package_file)}'**"
        #     else:
        #         if len(dep_dict[compid['componentIdentifier']]['paths']) > 0:
        #             message = message + f"Find dependency in {dep_dict[compid['componentIdentifier']]['paths'][0]}"
        #             message_markdown_footer = f"**Find dependency in {dep_dict[compid['componentIdentifier']]['paths'][0]}**"
        #
        #     print("INFO: " + message)
            globals.comment_on_pr_comments.append(comment_on_pr)
        #
        #     # Save message to include in Fix PR
            if upgrade_ver is not None:
                fix_pr_node['comments'].append(message)
                fix_pr_node['comments_markdown'].append(message_markdown)
                fix_pr_node['comments_markdown_footer'] = message_markdown_footer
        #
        #     result = dict()
        #     result['ruleId'] = vuln['name']
        #     message = dict()
        #     message['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {dep_dict[compid['componentIdentifier']]['compname']}."
        #     result['message'] = message
        #     locations = []
        #     loc = dict()
        #     loc['file'] = bu.remove_cwd_from_filename(package_file)
        #     # TODO: Can we reference the line number in the future, using project inspector?
        #     loc['line'] = package_line
        #
        #     tool_rule = dict()
        #     tool_rule['id'] = vuln['name']
        #     shortDescription = dict()
        #     shortDescription['text'] = f"{vuln['name']} - {vuln['vulnSeverity']} severity vulnerability in {dep_dict[compid['componentIdentifier']]['compname']}"
        #     tool_rule['shortDescription'] = shortDescription
        #     fullDescription = dict()
        #     fullDescription['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {dep_dict[compid['componentIdentifier']]['compname']}"
        #     tool_rule['fullDescription'] = fullDescription
        #     rule_help = dict()
        #     rule_help['text'] = ""
        #     if upgrade_ver is not None:
        #         rule_help['markdown'] = f"**{vuln['name']}:** *{vuln['description']}*\n\nRecommended to upgrade to version {upgrade_ver}.\n\n"
        #     else:
        #         rule_help['markdown'] = f"**{vuln['name']}:** *{vuln['description']}*\n\nNo upgrade available at this time.\n\n"
        #
        #     if dep_dict[compid['componentIdentifier']]['deptype'] == "Direct":
        #         rule_help['markdown'] = rule_help['markdown'] + f"Fix in package file '{bu.remove_cwd_from_filename(package_file)}'"
        #     else:
        #         if len(dep_dict[compid['componentIdentifier']]['paths']) > 0:
        #             rule_help['markdown'] = rule_help['markdown'] + \
        #                                     f" Find dependency in **{dep_dict[compid['componentIdentifier']]['paths'][0]}**."
        #
        #     tool_rule['help'] = rule_help
        #     defaultConfiguration = dict()
        #
        #     if vuln['vulnSeverity'] == "CRITICAL" or vuln['vulnSeverity'] == "HIGH":
        #         defaultConfiguration['level'] = "error"
        #     elif vuln['vulnSeverity'] == "MEDIUM":
        #         defaultConfiguration['level'] = "warning"
        #     else:
        #         defaultConfiguration['level'] = "note"
        #
        #     tool_rule['defaultConfiguration'] = defaultConfiguration
        #     properties = dict()
        #     properties['tags'] = ["security"]
        #     properties['security-severity'] = str(vuln['overallScore'])
        #     tool_rule['properties'] = properties
        #     globals.tool_rules.append(tool_rule)
        #
        #     location = dict()
        #     physicalLocation = dict()
        #     artifactLocation = dict()
        #     artifactLocation['uri'] = loc['file']
        #     physicalLocation['artifactLocation'] = artifactLocation
        #     region = dict()
        #     region['startLine'] = loc['line']
        #     physicalLocation['region'] = region
        #     location['physicalLocation'] = physicalLocation
        #     locations.append(location)
        #     result['locations'] = locations
        #
        #     # Calculate fingerprint using simply the CVE/BDSA - the scope is the project in GitHub, so this should be fairly accurate for identifying a unique issue.
        #     # Guidance from https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#preventing-duplicate-alerts-using-fingerprints
        #     # and https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012611
        #     # TODO Should this just leave it alone and let GitHub calculate it?
        #     partialFingerprints = dict()
        #     primaryLocationLineHash = hashlib.sha224(b"{vuln['name']}").hexdigest()
        #     partialFingerprints['primaryLocationLineHash'] = primaryLocationLineHash
        #     result['partialFingerprints'] = partialFingerprints
        #
        #     globals.results.append(result)
        #
        #     if dep_dict[compid['componentIdentifier']]['deptype'] == "Direct" and upgrade_ver is not None:
        #         globals.fix_pr_data[dep_dict[compid['componentIdentifier']]['compname'] + "@" + \
        #                             dep_dict[compid['componentIdentifier']]['compversion']] = fix_pr_node
        #         # fix_pr_data.append(fix_pr_node)


def main_process():

    # Process the main Rapid scan
    rapid_scan_data, dep_dict, direct_deps_to_upgrade, pm = process_bd_scan()

    # Get component data via async calls
    guidance_dict, version_dict, origin_dict = asyncio.run(async_main(direct_deps_to_upgrade, globals.bd))

    # Work out possible upgrades
    upgrade_dict = process_upgrades(direct_deps_to_upgrade, version_dict, guidance_dict, origin_dict)

    # Test upgrades using Detect Rapid scans
    upgrade_count, good_upgrades = test_upgrades(upgrade_dict, direct_deps_to_upgrade, pm)

    # Output the data
    create_scan_outputs(rapid_scan_data, good_upgrades, dep_dict)

    write_sarif()

    # Optionally generate Fix PR
    if globals.args.fix_pr and len(globals.fix_pr_data.values()) > 0:
        github_workflow.github_fix_pr()

    # Optionally comment on the pull request this is for
    if globals.args.comment_on_pr and len(globals.comment_on_pr_comments) > 0:
        github_workflow.github_pr_comment()

    if len(globals.comment_on_pr_comments) > 0:
        github_workflow.github_comment_on_pr_comments()

