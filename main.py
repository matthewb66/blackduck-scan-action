#!/usr/bin/env python

import argparse
import sys
import os
from BlackDuckUtils import Utils as bu
import globals
from blackduck import Client

import scan


if __name__ == "__main__":
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
    parser.add_argument("--upgrade_major", type=str, default="false", help="Offer upgrades to major versions, true or false")
    parser.add_argument("--comment_on_pr", type=str, default="false", help="Generate a comment on pull request, true or false")
    parser.add_argument("--sarif", type=str, default="blackduck-sarif.json", help="SARIF output file")
    parser.add_argument("--incremental_results", default="false", type=str, help="Compare to previous intelligent scan project - only report new/changed components")
    parser.add_argument("--upgrade_indirect", default="false", type=str, help="Attempt upgrade for vulnerable indirect dependencies by upgrading direct parents")
    parser.add_argument("--detect_opts", type=str, default="false", help="Passthrough options to Detect")

    globals.args = parser.parse_args()

    if globals.args.url is None:
        globals.args.url = os.getenv("BLACKDUCK_URL")
    if globals.args.token is None:
        globals.args.token = os.getenv("BLACKDUCK_API_TOKEN")
    if globals.args.trustcert is None:
        globals.args.trustcert = os.getenv("BLACKDUCK_TRUST_CERT")

    if (globals.args.url is None or globals.args.token is None):
        print(f"ERROR: Must specify Black Duck Hub URL and API Token")
        sys.exit(1)
    globals.args.mode = globals.args.mode.lower()
    if (globals.args.mode != "intelligent" and globals.args.mode != "rapid"):
        print(f"ERROR: Scanning mode must be intelligent or rapid")
        sys.exit(1)

    runargs = []
    if globals.args.fix_pr.lower() == 'true':
        globals.args.fix_pr = True
    else:
        globals.args.fix_pr = False

    if globals.args.upgrade_major.lower() == 'true':
        globals.args.upgrade_major = True
    else:
        globals.args.upgrade_major = False

    if globals.args.comment_on_pr.lower() == 'true':
        globals.args.comment_on_pr = True
    else:
        globals.args.comment_on_pr = False

    if globals.args.incremental_results.lower() == 'true':
        globals.args.incremental_results = True
    else:
        globals.args.incremental_results = False

    if globals.args.upgrade_indirect.lower() == 'true':
        globals.args.upgrade_indirect = True
    else:
        globals.args.upgrade_indirect = False

    if globals.args.trustcert.lower() == 'true':
        globals.args.trustcert = True
        runargs.append("--blackduck.trust.cert=true")
    else:
        globals.args.trustcert = False

    debug = int(globals.args.debug)
    globals.debug = int(globals.args.debug)

    runargs.extend(["--blackduck.url=" + globals.args.url, "--blackduck.api.token=" + globals.args.token,
                    "--detect.blackduck.scan.mode=" + globals.args.mode,
                    # "--detect.detector.buildless=true",
                    "--detect.output.path=" + globals.args.output, "--detect.cleanup=false"])

    if (globals.args.project is not None):
        runargs.extend(["--detect.project.name=" + globals.args.project])

    if (globals.args.version is not None):
        runargs.extend(["--detect.project.version.name=" + globals.args.version])

    print(f"INFO: Running Black Duck detect with the following options: {runargs}")

    if globals.args.detect_opts is not None and globals.args.detect_opts != '':
        runargs.append(globals.args.detect_opts)
    pvurl, projname, vername, detect_return_code = bu.run_detect(globals.detect_jar, runargs, True)

    print(f"INFO: Done with Black Duck run, return value {detect_return_code}")
    if (detect_return_code > 0 and detect_return_code != 3):
        print(f"ERROR: Black Duck detect returned exit code {detect_return_code}")
        sys.exit(detect_return_code)

    if (globals.args.mode == "intelligent"):
        sys.exit(0)

    # Todo - Add proxy support

    globals.bd = Client(token=globals.args.token,
                base_url=globals.args.url,
                verify=globals.args.trustcert,  # TLS certificate verification
                timeout=300)

    scan.main_process(globals.args.output)
