import json
import sys
import hashlib

from BlackDuckUtils import BlackDuckOutput as bo
from BlackDuckUtils import Utils as bu
from BlackDuckUtils import bdio as bdio
# from BlackDuckUtils import MavenUtils
# from BlackDuckUtils import NpmUtils
# from BlackDuckUtils import NugetUtils
from BlackDuckUtils import asyncdata as asyncdata


import globals
import github_workflow


def process_bd_scan(output):
    project_baseline_name, project_baseline_version, globals.detected_package_files = \
        bo.get_blackduck_status(output)

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
        comment_on_pr = ''
        message = ''
        message_markdown = ''
        # Loop the list of direct deps
        upgrade_ver = upgrade_dict[compid]

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

        max_vuln_severity = 0
        children_string = ''

        for child in children:
            # Find child in rapidscan data
            child_ns, child_name, child_ver = bu.parse_component_id(child)
            children_string += f"{child_name}/{child_ver}"
            for rscanitem in rapid_scan_data['items']:
                if rscanitem['componentIdentifier'] == child:
                    for vuln in rscanitem['policyViolationVulnerabilities']:
                        if max_vuln_severity < vuln['overallScore']:
                            max_vuln_severity = vuln['overallScore']
                        message_markdown_footer = ''
                        if upgrade_ver is not None:
                            message += f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* Recommended to upgrade to version {upgrade_ver}."
                            message_markdown += f"| {vuln['name']} | {vuln['vulnSeverity']} | {vuln['description']} | {child_ver} | {upgrade_ver} | "
                            comment_on_pr += f"| {vuln['name']} | {child} | {vuln['name']} |  {vuln['vulnSeverity']} | {vuln['violatingPolicies'][0]['policyName']} | {vuln['description']} | {child_ver} | {upgrade_ver} |"
                        else:
                            message += f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* No upgrade available at this time."
                            message_markdown += f"| {vuln['name']} | {vuln['vulnSeverity']} | {vuln['description']} | {child_ver} | {upgrade_ver} | "
                            comment_on_pr += f"| {vuln['name']} | {child} | {vuln['name']} | {vuln['vulnSeverity']} | {vuln['violatingPolicies'][0]['policyName']} | {vuln['description']} | {child_ver} | N/A |"
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

        # Save message to include in Fix PR
        if upgrade_ver is not None:
            fix_pr_node['comments'].append(message)
            fix_pr_node['comments_markdown'].append(message_markdown)
            fix_pr_node['comments_markdown_footer'] = message_markdown_footer

        result = dict()
        result['ruleId'] = name
        message = dict()
        message['text'] = f"This direct dependency has vulnerable children components {children_string} \
with max vulnerability score {max_vuln_severity}."
        result['message'] = message
        locations = []
        loc = dict()
        loc['file'] = bu.remove_cwd_from_filename(package_file)
        # TODO: Can we reference the line number in the future, using project inspector?
        loc['line'] = package_line

        tool_rule = dict()
        tool_rule['id'] = name
        short_description = dict()
        short_description['text'] = f"Vulnerable child dependencies (with max severity {max_vuln_severity}"
        tool_rule['shortDescription'] = short_description
        full_description = dict()
        full_description['text'] = f"This direct dependency has vulnerable children components {children_string} \
with max vulnerability score {max_vuln_severity}."

        tool_rule['fullDescription'] = full_description
        rule_help = dict()
        rule_help['text'] = ""
        if upgrade_ver is not None:
            rule_help['markdown'] = f"Recommended to upgrade to version {upgrade_ver}.\n\n"
        else:
            rule_help['markdown'] = f"No upgrade available at this time.\n\n"

        # if dep_dict[compid['componentIdentifier']]['deptype'] == "Direct":
        rule_help['markdown'] = rule_help['markdown'] + f"Fix in package file '{bu.remove_cwd_from_filename(package_file)}'"
        # else:
        #     if len(dep_dict[compid['componentIdentifier']]['paths']) > 0:
        #         rule_help['markdown'] = rule_help['markdown'] + \
        #                                 f" Find dependency in **{dep_dict[compid['componentIdentifier']]['paths'][0]}**."

        tool_rule['help'] = rule_help
        default_configuration = dict()

        if max_vuln_severity >= 7:
            default_configuration['level'] = "error"
        elif max_vuln_severity >= 4:
            default_configuration['level'] = "warning"
        else:
            default_configuration['level'] = "note"

        tool_rule['defaultConfiguration'] = default_configuration
        properties = dict()
        properties['tags'] = ["security"]
        properties['security-severity'] = str(max_vuln_severity)
        tool_rule['properties'] = properties
        globals.tool_rules.append(tool_rule)

        location = dict()
        physical_location = dict()
        artifact_location = dict()
        artifact_location['uri'] = loc['file']
        physical_location['artifactLocation'] = artifact_location
        region = dict()
        region['startLine'] = loc['line']
        physical_location['region'] = region
        location['physicalLocation'] = physical_location
        locations.append(location)
        result['locations'] = locations

        # Calculate fingerprint using simply the CVE/BDSA - the scope is the project in GitHub, so this should be fairly accurate for identifying a unique issue.
        # Guidance from https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#preventing-duplicate-alerts-using-fingerprints
        # and https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012611
        # TODO Should this just leave it alone and let GitHub calculate it?
        partial_fingerprints = dict()
        primary_location_line_hash = hashlib.sha224(b"{compid}").hexdigest()
        partial_fingerprints['primaryLocationLineHash'] = primary_location_line_hash
        result['partialFingerprints'] = partial_fingerprints

        globals.results.append(result)

        if upgrade_ver is not None:
            # globals.fix_pr_data[dep_dict[compid]['compname'] + "@" +
            #                     dep_dict[compid]['compversion']] = fix_pr_node
            a_comp = compid.replace(':', '@').replace('/', '@').split('@')
            globals.fix_pr_data[f"{a_comp[1]}@{a_comp[2]}"] = fix_pr_node

            # fix_pr_data.append(fix_pr_node)


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
        with open(sarif_file, "w") as fp:
            json.dump(code_security_scan_report, fp, indent=4)
    except Exception as e:
        print(f"ERROR: Unable to write to SARIF output file '{sarif_file} - '" + str(e))
        sys.exit(1)


def main_process(output):

    # Process the main Rapid scan
    rapid_scan_data, dep_dict, direct_deps_to_upgrade, pm = process_bd_scan(output)

    # Get component data via async calls
    # guidance_dict, version_dict, origin_dict = asyncio.run(async_main(direct_deps_to_upgrade, globals.bd))
    guidance_dict, version_dict, origin_dict = asyncdata.get_data_async(direct_deps_to_upgrade, globals.bd,
                                                                        globals.args.trustcert)

    # Work out possible upgrades
    # upgrade_dict = process_upgrades(direct_deps_to_upgrade, version_dict, guidance_dict, origin_dict)
    upgrade_dict = {}
    for dep in direct_deps_to_upgrade:
        upgrade_dict[dep] = bu.find_upgrade_versions(dep, version_dict[dep], origin_dict, guidance_dict[dep],
                                                     globals.args.upgrade_major)

    # Test upgrades using Detect Rapid scans
    good_upgrades = test_upgrades(upgrade_dict, direct_deps_to_upgrade, pm)

    # Output the data
    create_scan_outputs(rapid_scan_data, good_upgrades, dep_dict)

    if globals.args.sarif != '':
        write_sarif(globals.args.sarif)

    # Optionally generate Fix PR
    if globals.args.fix_pr and len(globals.fix_pr_data.values()) > 0:
        github_workflow.github_fix_pr()

    # Optionally comment on the pull request this is for
    if globals.args.comment_on_pr and len(globals.comment_on_pr_comments) > 0:
        github_workflow.github_pr_comment()

    if len(globals.comment_on_pr_comments) > 0:
        github_workflow.github_comment_on_pr_comments()
