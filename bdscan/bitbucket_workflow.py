import json
import random
import re
import sys
import os

import requests

from bdscan import globals

from github import Github
from BlackDuckUtils import MavenUtils
from BlackDuckUtils import NpmUtils
from BlackDuckUtils import NugetUtils


def github_create_pull_request_comment(g, pr, comments_markdown):
    globals.printdebug(f"DEBUG: Look up GitHub repo '{globals.github_repo}'")
    repo = g.get_repo(globals.github_repo)

    body = comments_markdown

    issue = repo.get_issue(number=pr.number)

    globals.printdebug(f"DEBUG: Create pull request review comment for pull request #{pr.number} "
                       f"with the following body:\n{body}")
    issue.create_comment(body)


def bitbucket_commit_file_and_create_fixpr(fix_pr_node, files_to_patch):
    if len(files_to_patch) == 0:
        print('BD-Scan-Action: WARN: Unable to apply fix patch - cannot determine containing package file')
        return False

    new_branch_seed = '%030x' % random.randrange(16 ** 30)
    # new_branch_seed = secrets.token_hex(15)
    new_branch_name = globals.bb_branch + "-snps-fix-pr-" + new_branch_seed

    globals.printdebug(f"DEBUG: Create branch '{new_branch_name}'")

    headers = {'content-type': 'application/json'}

    bb_url = f"{globals.bb_url}/rest/api/1.0/projects/{globals.bb_project}/repos/{globals.bb_repo}/branches"

    data = json.dumps({
        "name": new_branch_name,
        "startPoint": globals.bb_ref
    })
    r = requests.post(bb_url, verify=False, auth=(globals.bb_username, globals.bb_password), headers=headers, data=data)

    if (r.status_code > 250):
        print(f"ERROR: Unable to create BitBucket branch name={new_branch_name} ({r.status_code}:")
        print(r.json())
        sys.exit(1)

    commit_message = f"Update {fix_pr_node['componentName']} to fix known security vulnerabilities"

    # for file_to_patch in globals.files_to_patch:
    for pkgfile in fix_pr_node['projfiles']:
        globals.printdebug(f"DEBUG: Get SHA for file '{pkgfile}'")
        #orig_contents = repo.get_contents(pkgfile)

        # print(os.getcwd())
        globals.printdebug(f"DEBUG: Upload file '{pkgfile}'")
        try:
            with open(files_to_patch[pkgfile], 'r') as fp:
                new_contents = fp.read()
        except Exception as exc:
            print(f"BD-Scan-Action: ERROR: Unable to open package file '{files_to_patch[pkgfile]}'"
                  f" - {str(exc)}")
            return False

        globals.printdebug(f"DEBUG: Update file '{pkgfile}' with commit message '{commit_message}'")

        #headers = {'content-type': 'application/json'}
        headers = { }

        bb_url = f"{globals.bb_url}/rest/api/1.0/projects/{globals.bb_project}/repos/{globals.bb_repo}/browse/{pkgfile}"

        data = {
            "branch": new_branch_name,
            "content": new_contents,
            "message": commit_message,
            "sourceCommitId": globals.bb_ref
        }
        data_json=json.dumps(data)
        print(f"DEBUG: url={bb_url} data={data} headers={headers}")
        r = requests.put(bb_url, verify=False, auth=(globals.bb_username, globals.bb_password), headers=headers,
                          files=data)

        if (r.status_code > 250):
            print(f"ERROR: Unable to upload BitBucket file name={pkgfile} ({r.status_code})")
            sys.exit(1)

        print(f"DEBUG: Committed file {pkgfile}")

    pr_body = f"\n# Synopsys Black Duck Auto Pull Request\n" \
              f"Upgrade {fix_pr_node['componentName']} from version {fix_pr_node['versionFrom']} to " \
              f"{fix_pr_node['versionTo']} in order to fix security vulnerabilities:\n\n"

    pr_body = pr_body + "\n".join(fix_pr_node['comments_markdown']) + "\n\n" + fix_pr_node['comments_markdown_footer']
    globals.printdebug(f"DEBUG: Submitting pull request:")
    globals.printdebug(pr_body)



    pr_create_data = {
        "title": f"Black Duck: Upgrade {fix_pr_node['componentName']} to version "
                                f"{fix_pr_node['versionTo']} fix known security vulerabilities",
        "description": pr_body,
        "state": "OPEN",
        "open": True,
        "closed": False,
        "fromRef": {
            "id": f"refs/heads/{new_branch_name}",
            "name": None,
            "project": {
                "key": globals.bb_project
            }
        },
        "toRef": {
            "id": f"refs/heads/{globals.bb_branch}",
            "name": None,
            "project": {
                "key": globals.bb_project
            }
        },
        "locked": False
    }

    headers = {'content-type': 'application/json'}

    bb_url = f"{globals.bb_url}/rest/api/1.0/projects/{globals.bb_project}/repos/{globals.bb_repo}/pull-requests"

    print(f"DEBUG: url={bb_url} data={data_json} headers={headers}")
    r = requests.post(bb_url, verify=False, auth=(globals.bb_username, globals.bb_password), headers=headers,
                     json=pr_create_data)

    if (r.status_code > 250):
        print(f"ERROR: Unable to create BitBucket pull request for branch={new_branch_name} ({r.status_code}):")
        print(r.json())
        sys.exit(1)

    print(f"DEBUG: Created PR: {r.json()}")

    return True


def bitbucket_get_pull_requests():
    globals.printdebug(f"DEBUG: Index pull requests, Look up BitBucket repo '{globals.bb_repo}'")

    headers = {'content-type': 'application/json'}

    bb_url = f"{globals.bb_url}/rest/api/1.0/projects/{globals.bb_project}/repos/{globals.bb_repo}/pull-requests?limit=1"

    isLastPage = False
    nextPageStart = 0
    pulls = []
    while isLastPage == False:
        print(f"DEBUG: url={bb_url} headers={headers}")
        r = requests.get(bb_url + f"&start={nextPageStart}", verify=False, auth=(globals.bb_username, globals.bb_password), headers=headers)

        if (r.status_code > 250):
            print(f"ERROR: Unable to get BitBucket pull request activities number={globals.bb_pull_number} ({r.status_code}):")
            print(r.json())
            sys.exit(1)

        print(f"DEBUG: Got PR Comments: {r.json()}")

        for pull in r.json()['values']:
            pulls.append(pull)

        if 'nextPageStart' in r.json():
            nextPageStart = r.json()['nextPageStart']
        if 'isLastPage' in r.json() and r.json()['isLastPage'] == True:
            isLastPage = True

    if globals.debug: print(f"DEBUG: Got all pull requests={pulls}")

    pull_requests = []

    # TODO Should this handle other bases than master?
    for pull in pulls:
        globals.printdebug(f"DEBUG: Pull request number: {pull['id']}: {pull['title']}")
        pull_requests.append(pull['title'])

    return pull_requests


def bitbucket_fix_pr():
    globals.printdebug("DEBUG: Generating Fix Pull Requests")

    pulls = bitbucket_get_pull_requests()

    print(f"DEBUG: pulls={pulls}")

    globals.printdebug(f"fix_pr_data={globals.fix_pr_data}")
    ret = True
    for fix_pr_node in globals.fix_pr_data.values():
        globals.printdebug(f"DEBUG: Fix '{fix_pr_node['componentName']}' version '{fix_pr_node['versionFrom']}' in "
                           f"file '{fix_pr_node['projfiles']}' using ns '{fix_pr_node['ns']}' to version "
                           f"'{fix_pr_node['versionTo']}'")

        pull_request_title = f"Black Duck: Upgrade {fix_pr_node['componentName']} to version " \
                             f"{fix_pr_node['versionTo']} to fix known security vulnerabilities"
        if pull_request_title in pulls:
            globals.printdebug(f"DEBUG: Skipping pull request for {fix_pr_node['componentName']}' version "
                               f"'{fix_pr_node['versionFrom']} as it is already present")
            continue

        if fix_pr_node['ns'] == "npmjs":
            files_to_patch = NpmUtils.upgrade_npm_dependency(
                fix_pr_node['projfiles'],fix_pr_node['componentName'],fix_pr_node['versionFrom'],
                fix_pr_node['versionTo'])
        elif fix_pr_node['ns'] == "maven":
            files_to_patch = MavenUtils.upgrade_maven_dependency(
                fix_pr_node['projfiles'],fix_pr_node['componentName'],fix_pr_node['versionFrom'],
                fix_pr_node['versionTo'])
        elif fix_pr_node['ns'] == "nuget":
            files_to_patch = NugetUtils.upgrade_nuget_dependency(
                fix_pr_node['projfiles'],fix_pr_node['componentName'],fix_pr_node['versionFrom'],
                fix_pr_node['versionTo'])
        else:
            print(f"BD-Scan-Action: WARN: Generating a Fix PR for packages of type '{fix_pr_node['ns']}' is "
                  f"not supported yet")
            return False

        if len(files_to_patch) == 0:
            print('BD-Scan-Action: WARN: Unable to apply fix patch - cannot determine containing package file')
            return False

        if not bitbucket_commit_file_and_create_fixpr(fix_pr_node, files_to_patch):
            ret = False
    return ret


def bitbucket_pr_comment():
    headers = {'content-type': 'application/json'}

    bb_url = f"{globals.bb_url}/rest/api/1.0/projects/{globals.bb_project}/repos/{globals.bb_repo}/pull-requests/{globals.bb_pull_number}/activities?limit=1"

    isLastPage = False
    nextPageStart = 0
    pr_comments = []
    while isLastPage == False:
        print(f"DEBUG: url={bb_url} headers={headers}")
        r = requests.get(bb_url + f"&start={nextPageStart}", verify=False, auth=(globals.bb_username, globals.bb_password), headers=headers)

        if (r.status_code > 250):
            print(f"ERROR: Unable to get BitBucket pull request activities number={globals.bb_pull_number} ({r.status_code}):")
            print(r.json())
            sys.exit(1)

        print(f"DEBUG: Got PR Comments: {r.json()}")

        for pr_comment in r.json()['values']:
            pr_comments.append(pr_comment)

        if 'nextPageStart' in r.json():
            nextPageStart = r.json()['nextPageStart']
        if 'isLastPage' in r.json() and r.json()['isLastPage'] == True:
            isLastPage = True


    if globals.debug: print(f"DEBUG: Got All PR Comments: {pr_comments}")

    existing_comment = None
    existing_comment_version = 0
    # Check if existing comment
    for pr_comment in pr_comments:
        if "comment" not in pr_comment: continue
        globals.printdebug(f"DEBUG: Issue comment={pr_comment['comment']['text']}")
        if "Synopsys Black Duck - Vulnerabilities Reported" in pr_comment['comment']['text']:
            existing_comment = pr_comment['comment']['id']
            existing_comment_version = pr_comment['comment']['version']

    #    arr = re.split('[/#]', pr_comment['comment']['text'])
    #    if len(arr) >= 7:
    #        this_pullnum = arr[6]
    #        if not this_pullnum.isnumeric():
    #            continue
    #        this_pullnum = int(this_pullnum)
    #    else:
    #        continue
    #    if this_pullnum == pull_number_for_sha and globals.comment_on_pr_header in pr_comment.body:
    #        globals.printdebug(f"DEBUG: Found existing comment")
    #        existing_comment = pr_comment

    # Tricky here, we want everything all in one comment. So prepare a header, then append each of the comments and
    # create a comment
    # comments_markdown = [
    #     "| Component | Vulnerability | Severity |  Policy | Description | Current Ver | Upgrade to |",
    #     "| --- | --- | --- | --- | --- | --- | --- |"
    # ]
    #
    # for comment in globals.comment_on_pr_comments:
    #     comments_markdown.append(comment)
    comments_markdown = f"# {globals.comment_on_pr_header}\n" + "\n".join(globals.comment_on_pr_comments)

    if len(comments_markdown) > 65535:
        comments_markdown = comments_markdown[:65535]

    if existing_comment is not None:
        globals.printdebug(f"DEBUG: Update/edit existing comment for PR #{globals.bb_pull_number}\n{comments_markdown}")

        globals.printdebug(f"DEBUG: Create new comment for PR #{globals.bb_pull_number}")

        headers = {'content-type': 'application/json'}

        bb_url = f"{globals.bb_url}/rest/api/1.0/projects/{globals.bb_project}/repos/{globals.bb_repo}/pull-requests/{globals.bb_pull_number}/comments/{existing_comment}"

        data = {
            "text": comments_markdown,
            "version": existing_comment_version
        }
        r = requests.put(bb_url, verify=False, auth=(globals.bb_username, globals.bb_password), headers=headers,
                          json=data)

        if (r.status_code > 250):
            print(f"ERROR: Unable to update BitBucket PR comment on pull={globals.bb_pull_number} comment={existing_comment} ({r.status_code}:")
            print(r.json())
            sys.exit(1)

        print(f"DEBUG: Updated PR Comment {existing_comment}")
        sys.exit(1)
    else:
        globals.printdebug(f"DEBUG: Create new comment for PR #{globals.bb_pull_number}")

        headers = {'content-type': 'application/json'}

        bb_url = f"{globals.bb_url}/rest/api/1.0/projects/{globals.bb_project}/repos/{globals.bb_repo}/pull-requests/{globals.bb_pull_number}/comments"

        data = {
            "text": comments_markdown
        }
        r = requests.post(bb_url, verify=False, auth=(globals.bb_username, globals.bb_password), headers=headers,
                          json=data)

        if (r.status_code > 250):
            print(f"ERROR: Unable to create BitBucket PR comment on pull={globals.bb_pull_number} ({r.status_code}:")
            print(r.json())
            sys.exit(1)

        print(f"DEBUG: Created PR comment")

    return True


def github_set_commit_status(is_ok):
    globals.printdebug(f"DEBUG: Set check status for commit '{globals.github_sha}', connect to GitHub at "
                       f"{globals.github_api_url}")
    g = Github(globals.github_token, base_url=globals.github_api_url)

    globals.printdebug(f"DEBUG: Look up GitHub repo '{globals.github_repo}'")
    repo = g.get_repo(globals.github_repo)
    globals.printdebug(repo)

    if not is_ok:
        status = repo.get_commit(sha=globals.github_sha).create_status(
            state="failure",
            target_url="https://synopsys.com/software",
            description="Black Duck security scan found vulnerabilities",
            context="Synopsys Black Duck"
        )
    else:
        status = repo.get_commit(sha=globals.github_sha).create_status(
            state="success",
            target_url="https://synopsys.com/software",
            description="Black Duck security scan clear from vulnerabilities",
            context="Synopsys Black Duck"
        )

    globals.printdebug(f"DEBUG: Status:")
    globals.printdebug(status)


def check_files_in_commit():
    headers = {'content-type': 'application/json'}

    bb_url = f"{globals.bb_url}/rest/api/1.0/projects/{globals.bb_project}/repos/{globals.bb_repo}/commits/{globals.bb_ref}/changes?limit=1"

    isLastPage = False
    nextPageStart = 0
    commits = []
    while isLastPage == False:
        print(f"DEBUG: url={bb_url} headers={headers}")
        r = requests.get(bb_url + f"&start={nextPageStart}", verify=False, auth=(globals.bb_username, globals.bb_password), headers=headers)

        if (r.status_code > 250):
            print(f"ERROR: Unable to get BitBucket PR commit history for ref={globals.bb_ref} ({r.status_code}:")
            print(r.json())
            sys.exit(1)

        if globals.debug: print(f"DEBUG: BitBucket response={json.dumps(r.json(), indent=4)}")

        for commit in r.json()['values']:
            commits.append(commit)

        if 'nextPageStart' in r.json():
            nextPageStart = r.json()['nextPageStart']
        if 'isLastPage' in r.json() and r.json()['isLastPage'] == True:
            isLastPage = True

    print(f"DEBUG: Full list of commits={commits}")

    found = False
    for commit_file in commits:
        if globals.debug: print(f"DEBUG: commit_file={commit_file['path']['name']}")
        if os.path.basename(commit_file['path']['name']) in globals.pkg_files:
            found = True
            break

        if os.path.splitext(commit_file['path']['name'])[-1] in globals.pkg_exts:
            found = True
            break

    return found


def check_files_in_pull_request():
    headers = {'content-type': 'application/json'}

    bb_url = f"{globals.bb_url}/rest/api/1.0/projects/{globals.bb_project}/repos/{globals.bb_repo}/pull-requests/{globals.bb_pull_number}/changes?limit=1"

    isLastPage = False
    nextPageStart = 0
    changes = []
    while isLastPage == False:
        print(f"DEBUG: url={bb_url} headers={headers}")
        r = requests.get(bb_url + f"&start={nextPageStart}", verify=False, auth=(globals.bb_username, globals.bb_password), headers=headers)

        if (r.status_code > 250):
            print(f"ERROR: Unable to get BitBucket PR change history for ref={globals.bb_ref} ({r.status_code}:")
            print(r.json())
            sys.exit(1)

        if globals.debug: print(f"DEBUG: BitBucket response={json.dumps(r.json(), indent=4)}")

        for change in r.json()['values']:
            changes.append(change)

        if 'nextPageStart' in r.json():
            nextPageStart = r.json()['nextPageStart']
        if 'isLastPage' in r.json() and r.json()['isLastPage'] == True:
            isLastPage = True

    print(f"DEBUG: Full list of changes={changes}")

    found = False
    for commit_file in changes:
        if os.path.basename(commit_file['path']['name']) in globals.pkg_files:
            found = True
            break

        if os.path.splitext(commit_file['path']['name'])[-1] in globals.pkg_exts:
            found = True
            break

    return found
