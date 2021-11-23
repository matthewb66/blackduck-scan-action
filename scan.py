# import argparse
# import glob
import hashlib
import json
# import os
# import random
import re
# import shutil
import sys
# import zipfile
import aiohttp
import asyncio

import networkx as nx
from BlackDuckUtils import BlackDuckOutput as bo
from BlackDuckUtils import Utils as bu
from BlackDuckUtils import bdio as bdio
# from BlackDuckUtils import globals as bdglobals
from BlackDuckUtils import MavenUtils
from BlackDuckUtils import NpmUtils

# from blackduck import Client
import globals
import github_workflow


# TODO Better to read BD API Token from environment variable
# bd_apitoken = os.getenv("BLACKDUCK_TOKEN")
# if (bd_apitoken == None or bd_apitoken == ""):
#    print("ERROR: Please set BLACKDUCK_TOKEN in environment before running")
#    sys.exit(1)


def process_bd_scan():

    project_baseline_name, project_baseline_version, globals.detected_package_files = \
        bo.get_blackduck_status(globals.args.output)

    print(f"INFO: Running for project '{project_baseline_name}' version '{project_baseline_version}'")

    # Look up baseline data
    pvurl = bu.get_projver(globals.bd, project_baseline_name, project_baseline_version)
    globals.baseline_comp_cache = dict()
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
                if not comp['componentName'] in globals.baseline_comp_cache:
                    globals.baseline_comp_cache[comp['componentName']] = dict()
                # if (baseline_comp_cache[comp['componentName']] == None): baseline_comp_cache[comp['componentName']] = dict()
                globals.baseline_comp_cache[comp['componentName']][comp['componentVersionName']] = 1
                # baseline_comp_cache[comp['componentName']] = comp['componentVersionName']
            globals.printdebug(f"DEBUG: Baseline component cache=" + json.dumps(globals.baseline_comp_cache, indent=4))
            globals.printdebug(f"DEBUG: Generated baseline component cache")

    globals.bdio_graph, globals.bdio_projects = bdio.get_bdio_dependency_graph(globals.args.output)

    if len(globals.bdio_projects) == 0:
        print("ERROR: Unable to find base project in BDIO file")
        sys.exit(1)

    globals.rapid_scan_data = bo.get_rapid_scan_results(globals.args.output, globals.bd)

    return pvurl


async def async_main(compitems, bd):
    token = bd.session.auth.bearer_token

    async with aiohttp.ClientSession() as session:
        compid_tasks = []

        for comp in compitems:
            compid_task = asyncio.ensure_future(async_get_compids(session, bd.base_url, comp, token))
            compid_tasks.append(compid_task)

        print('Getting componentids ... ')
        all_compids = dict(await asyncio.gather(*compid_tasks))
        await asyncio.sleep(0.250)

    async with aiohttp.ClientSession() as session:
        upgradeguidance_tasks = []

        for comp in compitems:
            upgradeguidance_task = asyncio.ensure_future(async_get_guidance(session, comp, all_compids, token))
            upgradeguidance_tasks.append(upgradeguidance_task)

        print('Getting component data ... ')
        all_upgradeguidances = dict(await asyncio.gather(*upgradeguidance_tasks))
        await asyncio.sleep(0.250)

    return all_upgradeguidances


async def async_get_compids(session, baseurl, comp, token):
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
        'q': [comp['componentIdentifier']]
    }
    # search_results = bd.get_items('/api/components', params=params)
    async with session.get(baseurl + '/api/components', headers=headers, params=params, ssl=ssl) as resp:
        found_comps = await resp.json()

    print(found_comps['items'])

    if len(found_comps['items']) != 1:
        return None, None
    found = found_comps['items'][0]

    return comp['componentIdentifier'], found['version'] + '/upgrade-guidance'


async def async_get_guidance(session, comp, compids, token):
    if not globals.args.trustcert:
        ssl = False
    else:
        ssl = None

    headers = {
        'accept': "application/vnd.blackducksoftware.component-detail-5+json",
        'Authorization': f'Bearer {token}',
    }
    if 'componentIdentifier' in comp and comp['componentIdentifier'] in compids:
        gurl = compids[comp['componentIdentifier']]
    else:
        return None, None

    print(gurl)
    async with session.get(gurl, headers=headers, ssl=ssl) as resp:
        component_upgrade_data = await resp.json()

    print(component_upgrade_data)
    if "longTerm" in component_upgrade_data.keys():
        longTerm = component_upgrade_data['longTerm']['versionName']
    else:
        longTerm = ''

    if "shortTerm" in component_upgrade_data.keys():
        shortTerm = component_upgrade_data['shortTerm']['versionName']
    else:
        shortTerm = ''

    return comp['componentIdentifier'], [shortTerm, longTerm]


def process_rapid_scan_results():
    upgrade_dict = asyncio.run(async_main(globals.rapid_scan_data['items'], globals.bd))

    for item in globals.rapid_scan_data['items']:
        globals.printdebug(f"DEBUG: Component: {item['componentIdentifier']}")
        globals.printdebug(item)

        comp_ns, comp_name, comp_version = bu.parse_component_id(item['componentIdentifier'])

        # If comparing to baseline, look up in cache and continue if already exists
        if globals.args.incremental_results and item['componentName'] in globals.baseline_comp_cache:
            if (item['versionName'] in globals.baseline_comp_cache[item['componentName']] and
                    globals.baseline_comp_cache[item['componentName']][item['versionName']] == 1):
                globals.printdebug(f"DEBUG:   Skipping component {item['componentName']} \
version {item['versionName']} because it was already seen in baseline")
                continue
            else:
                globals.printdebug(f"DEBUG:   Including component {item['componentName']} \
version {item['versionName']} because it was not seen in baseline")

        # Is this a direct dependency?
        dependency_type = "Direct"

        # Track the root dependencies
        dependency_paths = []
        direct_ancestors = dict()

        globals.printdebug(f"DEBUG: Looking for {item['componentIdentifier']}")
        globals.printdebug(f"DEBUG: comp_ns={comp_ns} comp_name={comp_name} comp_version={comp_version}")

        # Matching in the BDIO requires an http: prefix
        if comp_ns == "npmjs":
            node_http_name = NpmUtils.convert_to_bdio(item['componentIdentifier'])
        elif comp_ns == "maven":
            node_http_name = MavenUtils.convert_to_bdio(item['componentIdentifier'])
        else:
            print(f"ERROR: Domain '{comp_ns}' not supported yet")
            sys.exit(1)

        globals.printdebug(f"DEBUG: Looking for {node_http_name}")
        ans = nx.ancestors(globals.bdio_graph, node_http_name)
        ans_list = list(ans)
        globals.printdebug(f"DEBUG:   Ancestors are: {ans_list}")
        pred = nx.DiGraph.predecessors(globals.bdio_graph, node_http_name)
        pred_list = list(pred)
        globals.printdebug(f"DEBUG:   Predecessors are: {ans_list}")
        if len(ans_list) != 1:
            dependency_type = "Transitive"

            # If this is a transitive dependency, what are the flows?
            for proj in globals.bdio_projects:
                dep_paths = nx.all_simple_paths(globals.bdio_graph, source=proj, target=node_http_name)
                globals.printdebug(f"DEBUG: Paths to '{node_http_name}'")
                paths = []
                for path in dep_paths:
                    # First generate a string for easy output and reading
                    path_modified = path
                    path_modified.pop(0)
                    # Subtract http:<domain>/
                    path_modified_trimmed = [re.sub(r'http:.*?/', '', path_name) for path_name in path_modified]
                    # Change / to @
                    path_modified_trimmed = [re.sub(r'/', '@', path_name) for path_name in path_modified_trimmed]
                    pathstr = " -> ".join(path_modified_trimmed)
                    globals.printdebug(f"DEBUG:   path={pathstr}")
                    dependency_paths.append(pathstr)
                    if globals.args.upgrade_indirect:
                        # Then log the direct dependencies directly
                        direct_dep = path_modified_trimmed[0]
                        direct_name = direct_dep.split('@')[0]
                        direct_version = direct_dep.split('@')[1]

                        direct_ancestors[direct_dep] = 1
                        # if (globals.debug): print(f"DEBUG: Direct ancestor: {direct_dep} is of type {node_domain}")
                        bu.attempt_indirect_upgrade(comp_ns, comp_version, direct_name, direct_version,
                                                    globals.detect_jar)

        # Get component upgrade advice
        # shortTerm, longTerm = bu.get_upgrade_guidance(globals.bd, item['componentIdentifier'])
        shortTerm, longTerm = upgrade_dict[item['componentIdentifier']]

        upgrade_version = None
        if globals.args.upgrade_major:
            if longTerm is not None and longTerm != '':
                upgrade_version = longTerm
        else:
            if shortTerm is not None and shortTerm != '':
                upgrade_version = shortTerm

        globals.printdebug(f"DEUBG: Detected package files={globals.detected_package_files} item={item}")
        package_file, package_line = bu.detect_package_file(globals.detected_package_files,
                                                            item['componentIdentifier'], item['componentName'])

        globals.printdebug(f"DEBUG: package file for {item['componentIdentifier']} is {package_file} on line {package_line} type is {dependency_type}")

        fix_pr_node = dict()
        if dependency_type == "Direct" and upgrade_version is not None:
            fix_pr_node['componentName'] = comp_name
            fix_pr_node['versionFrom'] = comp_version
            fix_pr_node['versionTo'] = upgrade_version
            fix_pr_node['ns'] = comp_ns
            fix_pr_node['filename'] = bu.remove_cwd_from_filename(package_file)
            fix_pr_node['comments'] = []
            fix_pr_node['comments_markdown'] = ["| ID | Severity | Description | Vulnerable version | Upgrade to |", "| --- | --- | --- | --- | --- |"]
            fix_pr_node['comments_markdown_footer'] = ""

        # Loop through policy violations and append to SARIF output data

        globals.printdebug(f"DEBUG: Loop through policy violations")
        globals.printdebug(item['policyViolationVulnerabilities'])

        for vuln in item['policyViolationVulnerabilities']:
            message_markdown_footer = ''
            if upgrade_version is not None:
                message = f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* Recommended to upgrade to version {upgrade_version}. {dependency_type} dependency."
                message_markdown = f"| {vuln['name']} | {vuln['vulnSeverity']} | {vuln['description']} | {comp_version} | {upgrade_version} | "
                comment_on_pr = f"| {vuln['name']} | {dependency_type} | {vuln['name']} |  {vuln['vulnSeverity']} | {vuln['violatingPolicies'][0]['policyName']} | {vuln['description']} | {comp_version} | {upgrade_version} |"
            else:
                message = f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* No upgrade available at this time. {dependency_type} dependency."
                message_markdown = f"| {vuln['name']} | {vuln['vulnSeverity']} | {vuln['description']} | {comp_version} | {upgrade_version} | "
                comment_on_pr = f"| {vuln['name']} | {dependency_type} | {vuln['name']} | {vuln['vulnSeverity']} | {vuln['violatingPolicies'][0]['policyName']} | {vuln['description']} | {comp_version} | N/A |"

            if dependency_type == "Direct":
                message = message + f"Fix in package file '{bu.remove_cwd_from_filename(package_file)}'"
                message_markdown_footer = f"**Fix in package file '{bu.remove_cwd_from_filename(package_file)}'**"
            else:
                if len(dependency_paths) > 0:
                    message = message + f"Find dependency in {dependency_paths[0]}"
                    message_markdown_footer = f"**Find dependency in {dependency_paths[0]}**"

            print("INFO: " + message)
            globals.comment_on_pr_comments.append(comment_on_pr)

            # Save message to include in Fix PR
            if dependency_type == "Direct" and upgrade_version is not None:
                fix_pr_node['comments'].append(message)
                fix_pr_node['comments_markdown'].append(message_markdown)
                fix_pr_node['comments_markdown_footer'] = message_markdown_footer

            result = dict()
            result['ruleId'] = vuln['name']
            message = dict()
            message['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {comp_name}."
            result['message'] = message
            locations = []
            loc = dict()
            loc['file'] = bu.remove_cwd_from_filename(package_file)
            # TODO: Can we reference the line number in the future, using project inspector?
            loc['line'] = package_line

            tool_rule = dict()
            tool_rule['id'] = vuln['name']
            shortDescription = dict()
            shortDescription['text'] = f"{vuln['name']} - {vuln['vulnSeverity']} severity vulnerability in {comp_name}"
            tool_rule['shortDescription'] = shortDescription
            fullDescription = dict()
            fullDescription['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {comp_name}"
            tool_rule['fullDescription'] = fullDescription
            rule_help = dict()
            rule_help['text'] = ""
            if upgrade_version is not None:
                rule_help['markdown'] = f"**{vuln['name']}:** *{vuln['description']}*\n\nRecommended to upgrade to version {upgrade_version}.\n\n"
            else:
                rule_help['markdown'] = f"**{vuln['name']}:** *{vuln['description']}*\n\nNo upgrade available at this time.\n\n"

            if dependency_type == "Direct":
                rule_help['markdown'] = rule_help['markdown'] + f"Fix in package file '{bu.remove_cwd_from_filename(package_file)}'"
            else:
                if len(dependency_paths) > 0:
                    rule_help['markdown'] = rule_help['markdown'] + f" Find dependency in **{dependency_paths[0]}**."

            tool_rule['help'] = rule_help
            defaultConfiguration = dict()

            if vuln['vulnSeverity'] == "CRITICAL" or vuln['vulnSeverity'] == "HIGH":
                defaultConfiguration['level'] = "error"
            elif vuln['vulnSeverity'] == "MEDIUM":
                defaultConfiguration['level'] = "warning"
            else:
                defaultConfiguration['level'] = "note"

            tool_rule['defaultConfiguration'] = defaultConfiguration
            properties = dict()
            properties['tags'] = ["security"]
            properties['security-severity'] = str(vuln['overallScore'])
            tool_rule['properties'] = properties
            globals.tool_rules.append(tool_rule)

            location = dict()
            physicalLocation = dict()
            artifactLocation = dict()
            artifactLocation['uri'] = loc['file']
            physicalLocation['artifactLocation'] = artifactLocation
            region = dict()
            region['startLine'] = loc['line']
            physicalLocation['region'] = region
            location['physicalLocation'] = physicalLocation
            locations.append(location)
            result['locations'] = locations

            # Calculate fingerprint using simply the CVE/BDSA - the scope is the project in GitHub, so this should be fairly accurate for identifying a unique issue.
            # Guidance from https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#preventing-duplicate-alerts-using-fingerprints
            # and https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012611
            # TODO Should this just leave it alone and let GitHub calculate it?
            partialFingerprints = dict()
            primaryLocationLineHash = hashlib.sha224(b"{vuln['name']}").hexdigest()
            partialFingerprints['primaryLocationLineHash'] = primaryLocationLineHash
            result['partialFingerprints'] = partialFingerprints

            globals.results.append(result)

            if dependency_type == "Direct" and upgrade_version is not None:
                globals.fix_pr_data[comp_name + "@" + comp_name] = fix_pr_node
                # fix_pr_data.append(fix_pr_node)


def main_scan_process():

    process_bd_scan()

    # Prepare SARIF output structures
    runs = []
    run = dict()

    component_match_types = dict()
    components = dict()

    process_rapid_scan_results()

    run['results'] = globals.results
    runs.append(run)

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

    # Optionally generate Fix PR
    if globals.args.fix_pr and len(globals.fix_pr_data.values()) > 0:
        github_workflow.github_fix_pr()

    # Optionally comment on the pull request this is for
    if globals.args.comment_on_pr and len(globals.comment_on_pr_comments) > 0:
        github_workflow.github_pr_comment()

    if len(globals.comment_on_pr_comments) > 0:
        github_workflow.github_comment_on_pr_comments()

    #     print(f"INFO: Vulnerable components found, returning exit code 1")
    #     sys.exit(1)
    # else:
    #     print(f"INFO: No new components found, nothing to report")
    #     sys.exit(0)
