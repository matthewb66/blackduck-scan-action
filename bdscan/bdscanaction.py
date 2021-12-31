#!/usr/bin/env python

import argparse
import sys
import os
from bdscan import globals
from bdscan import scan


def main():
    # os.chdir('/Users/mbrad/working/duck_hub_ORI')
    parser = argparse.ArgumentParser(description="Run Black Duck Security Scan")
    parser.add_argument('--debug', default=0, help='set debug level [0-9]')
    parser.add_argument("--url", required=True, type=str, help="Black Duck Hub URL")
    parser.add_argument("--token", required=True, type=str, help="Black Duck Hub Token")
    parser.add_argument("--trustcert", default="false", type=str, help="Black Duck trust certificate")
    parser.add_argument("--project", type=str, help="Project name")
    parser.add_argument("--version", type=str, help="Project version name")
    parser.add_argument("--mode", default="rapid", type=str,
                        help="Black Duck scanning mode, either intelligent or rapid")
    parser.add_argument("--output", default="blackduck-output", type=str, help="Output directory")
    parser.add_argument("--fix_pr", type=str, default="false", help="Create a Fix PR, true or false")
    parser.add_argument("--upgrade_major", type=str, default="false",
                        help="Offer upgrades to major versions, true or false")
    parser.add_argument("--comment_on_pr", type=str, default="false",
                        help="Generate a comment on pull request, true or false")
    parser.add_argument("--sarif", type=str, help="SARIF output file")
    parser.add_argument("--incremental_results", default="false", type=str,
                        help="Compare to previous intelligent scan project - only report new/changed components")
    parser.add_argument("--upgrade_indirect", default="false", type=str,
                        help="Attempt upgrade for vulnerable indirect dependencies by upgrading direct parents")
    parser.add_argument("--detect_opts", type=str, help="Passthrough options to Detect")

    globals.args = parser.parse_args()

    print('--- BD PLUGIN CONFIGURATION ---------------------------------------------')

    if globals.args.url is None:
        globals.args.url = os.getenv("BLACKDUCK_URL")
    if globals.args.token is None:
        globals.args.token = os.getenv("BLACKDUCK_API_TOKEN")

    if globals.args.url is None or globals.args.token is None:
        print(f"ERROR: Must specify Black Duck Hub URL and API Token")
        sys.exit(1)

    print(f'- BD URL {globals.args.url}')
    print(f'- BD Token *************')
    if globals.args.trustcert.lower() == 'true':
        globals.args.trustcert = True
    else:
        globals.args.trustcert = os.getenv("BLACKDUCK_TRUST_CERT")
        if globals.args.trustcert is None:
            globals.args.trustcert = False
        else:
            globals.args.trustcert = True

    runargs = []
    if globals.args.trustcert:
        runargs.append("--blackduck.trust.cert=true")
        print('- Trust BD server certificate')

    globals.args.mode = globals.args.mode.lower()
    if globals.args.mode == 'full':
        globals.args.mode = 'intelligent'

    if globals.args.mode != "intelligent" and globals.args.mode != "rapid":
        print(f"ERROR: Scanning mode must be intelligent or rapid")
        sys.exit(1)

    if globals.args.mode == 'intelligent':
        print('- Run intelligent (full) scan')

    if globals.args.mode == 'rapid':
        print('- Run Rapid scan')

    if globals.args.fix_pr.lower() == 'true':
        globals.args.fix_pr = True
        print('- Create Fix PR')
    else:
        globals.args.fix_pr = False

    if globals.args.comment_on_pr.lower() == 'true':
        globals.args.comment_on_pr = True
        print('- Add comment to existing PR')
    else:
        globals.args.comment_on_pr = False

    if globals.args.upgrade_major.lower() == 'true':
        if not globals.args.comment_on_pr and not globals.args.fix_pr:
            print('WARNING: Upgrade major option specified but fix or comment on PR not configured - Ignoring')
            globals.args.upgrade_major = False
        else:
            globals.args.upgrade_major = True
            print('- Allow major version upgrades')
    else:
        globals.args.upgrade_major = False

    if globals.args.incremental_results.lower() == 'true':
        globals.args.incremental_results = True
        print('- Calculate incremental results (since last full/intelligent scan')
    else:
        globals.args.incremental_results = False

    if globals.args.upgrade_indirect.lower() == 'true':
        print('- Calculate upgrades for direct dependencies to address indirect vulnerabilities')
        globals.args.upgrade_indirect = True
    else:
        globals.args.upgrade_indirect = False

    debug = int(globals.args.debug)
    globals.debug = int(globals.args.debug)

    runargs.extend(["--blackduck.url=" + globals.args.url,
                    "--blackduck.api.token=" + globals.args.token,
                    "--detect.blackduck.scan.mode=" + globals.args.mode,
                    # "--detect.detector.buildless=true",
                    "--detect.output.path=" + globals.args.output,
                    # "--detect.bdio.file.name=scanout.bdio",
                    "--detect.cleanup=false"])

    if globals.args.project is not None:
        runargs.append("--detect.project.name=" + globals.args.project)
        print(f'- BD project name {globals.args.project}')

    if globals.args.version is not None:
        runargs.append("--detect.project.version.name=" + globals.args.version)
        print(f'- BD project version name {globals.args.version}')

    if globals.args.detect_opts is not None:
        print(f"- Add options to Detect scan {globals.args.detect_opts}")
        runargs.append(globals.args.detect_opts)

    if globals.args.sarif is not None:
        print(f"- Output GH SARIF to {globals.args.sarif}")

    print('-------------------------------------------------------------------------')
    print(f"INFO: Running Black Duck detect with the following options: {runargs}")

    scan.main_process(globals.args.output, runargs)


if __name__ == "__main__":
    main()
