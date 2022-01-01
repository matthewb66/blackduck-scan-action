import random
import re
import sys
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


def github_commit_file_and_create_fixpr(g, fix_pr_node):
    if len(globals.files_to_patch) == 0:
        print('WARNING: Unable to apply fix patch - cannot determine containing package file')
        return False
    globals.printdebug(f"DEBUG: Look up GitHub repo '{globals.github_repo}'")
    repo = g.get_repo(globals.github_repo)
    globals.printdebug(repo)

    globals.printdebug(f"DEBUG: Get HEAD commit from '{globals.github_repo}'")
    commit = repo.get_commit('HEAD')
    globals.printdebug(commit)

    new_branch_seed = '%030x' % random.randrange(16 ** 30)
    # new_branch_seed = secrets.token_hex(15)
    new_branch_name = globals.github_ref + "-snps-fix-pr-" + new_branch_seed
    globals.printdebug(f"DEBUG: Create branch '{new_branch_name}'")
    ref = repo.create_git_ref("refs/heads/" + new_branch_name, commit.sha)
    globals.printdebug(ref)

    commit_message = f"Update {fix_pr_node['componentName']} to fix known security vulnerabilities"

    for file_to_patch in globals.files_to_patch:
        globals.printdebug(f"DEBUG: Get SHA for file '{file_to_patch}'")
        file = repo.get_contents(file_to_patch)

        globals.printdebug(f"DEBUG: Upload file '{file_to_patch}'")
        try:
            with open(globals.files_to_patch[file_to_patch], 'r') as fp:
                file_contents = fp.read()
        except Exception as exc:
            print(f"ERROR: Unable to open package file '{globals.files_to_patch[file_to_patch]}' - {str(exc)}")
            return False

        globals.printdebug(f"DEBUG: Update file '{file_to_patch}' with commit message '{commit_message}'")
        file = repo.update_file(file_to_patch, commit_message, file_contents, file.sha, branch=new_branch_name)

    pr_body = f'''
Pull request submitted by Synopsys Black Duck to upgrade {fix_pr_node['componentName']} from version 
{fix_pr_node['versionFrom']} to {fix_pr_node['versionTo']} in order to fix the known security vulnerabilities:

'''
    pr_body = pr_body + "\n".join(fix_pr_node['comments_markdown']) + "\n\n" + fix_pr_node['comments_markdown_footer']
    globals.printdebug(f"DEBUG: Submitting pull request:")
    globals.printdebug(pr_body)
    pr = repo.create_pull(title=f"Black Duck: Upgrade {fix_pr_node['componentName']} to version "
                                f"{fix_pr_node['versionTo']} fix known security vulerabilities",
                          body=pr_body, head=new_branch_name, base="master")
    return True


def github_get_pull_requests(g):
    globals.printdebug(f"DEBUG: Index pull requests, Look up GitHub repo '{globals.github_repo}'")
    repo = g.get_repo(globals.github_repo)
    globals.printdebug(repo)

    pull_requests = []

    # TODO Should this handle other bases than master?
    pulls = repo.get_pulls(state='open', sort='created', base='master', direction="desc")
    for pull in pulls:
        globals.printdebug(f"DEBUG: Pull request number: {pull.number}: {pull.title}")
        pull_requests.append(pull.title)

    return pull_requests


def github_fix_pr():
    # fix_pr_components = dict()
    if (globals.github_token is None or globals.github_repo is None or globals.github_branch is None or
            globals.github_api_url is None):
        print("ERROR: Cannot find GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF and/or GITHUB_API_URL in the "
              "environment - are you running from a GitHub action?")
        return False

    globals.printdebug(f"DEBUG: Connect to GitHub at {globals.github_api_url}")
    g = Github(globals.github_token, base_url=globals.github_api_url)

    globals.printdebug("DEBUG: Generating Fix Pull Requests")

    pulls = github_get_pull_requests(g)

    globals.printdebug(f"fix_pr_data={globals.fix_pr_data}")
    ret = True
    for fix_pr_node in globals.fix_pr_data.values():
        globals.printdebug(f"DEBUG: Fix '{fix_pr_node['componentName']}' version '{fix_pr_node['versionFrom']}' in "
                           f"file '{fix_pr_node['filename']}' using ns '{fix_pr_node['ns']}' to version "
                           f"'{fix_pr_node['versionTo']}'")

        pull_request_title = f"Black Duck: Upgrade {fix_pr_node['componentName']} to version " \
                             f"{fix_pr_node['versionTo']} fix known security vulerabilities"
        if pull_request_title in pulls:
            globals.printdebug(f"DEBUG: Skipping pull request for {fix_pr_node['componentName']}' version "
                               f"'{fix_pr_node['versionFrom']} as it is already present")
            continue

        if fix_pr_node['ns'] == "npmjs":
            globals.files_to_patch = NpmUtils.upgrade_npm_dependency(fix_pr_node['filename'],
                                                                     fix_pr_node['componentName'],
                                                                     fix_pr_node['versionFrom'],
                                                                     fix_pr_node['versionTo'])
        elif fix_pr_node['ns'] == "maven":
            globals.files_to_patch = MavenUtils.upgrade_maven_dependency(fix_pr_node['filename'],
                                                                         fix_pr_node['componentName'],
                                                                         fix_pr_node['versionFrom'],
                                                                         fix_pr_node['versionTo'])
        elif fix_pr_node['ns'] == "nuget":
            globals.files_to_patch = NugetUtils.upgrade_nuget_dependency(fix_pr_node['filename'],
                                                                         fix_pr_node['componentName'],
                                                                         fix_pr_node['versionFrom'],
                                                                         fix_pr_node['versionTo'])
        else:
            print(f"INFO: Generating a Fix PR for packages of type '{fix_pr_node['ns']}' is not supported yet")
            return False

        if len(globals.files_to_patch) == 0:
            print('WARNING: Unable to apply fix patch - cannot determine containing package file')
            return False

        if not github_commit_file_and_create_fixpr(g, fix_pr_node):
            ret = False
    return ret


def github_pr_comment():
    if (globals.github_token is None or globals.github_repo is None or globals.github_ref is None or
            globals.github_api_url is None or globals.github_sha is None):
        print("ERROR: Cannot find GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF, GTIHUB_SHA and/or GITHUB_API_URL in the "
              "environment - are you running from a GitHub action?")
        return False

    globals.printdebug(f"DEBUG: Connect to GitHub at {globals.github_api_url}")
    g = Github(globals.github_token, base_url=globals.github_api_url)

    globals.printdebug(f"DEBUG: Look up GitHub repo '{globals.github_repo}'")
    repo = g.get_repo(globals.github_repo)
    globals.printdebug(repo)

    globals.printdebug(f"DEBUG: Look up GitHub ref '{globals.github_ref}'")
    # Remove leading refs/ as the API will prepend it on it's own
    # Actually look pu the head not merge ref to get the latest commit so
    # we can find the pull request
    ref = repo.get_git_ref(globals.github_ref[5:].replace("/merge", "/head"))
    globals.printdebug(ref)

    pull_number_for_sha = None
    m = re.search('pull\/(.+?)\/', globals.github_ref)
    if m:
        pull_number_for_sha = int(m.group(1))

    globals.printdebug(f"DEBUG: Pull request #{pull_number_for_sha}")

    if pull_number_for_sha is None:
        print(f"ERROR: Unable to find pull request #{pull_number_for_sha}")
        return False

    pr = repo.get_pull(pull_number_for_sha)

    pr_comments = repo.get_issues_comments(sort='updated', direction='desc')
    existing_comment = None
    for pr_comment in pr_comments:
        globals.printdebug(f"DEBUG: Issue comment={pr_comment.body}")
        if "Synopsys Black Duck XXXX" in pr_comment.body:
            globals.printdebug(f"DEBUG: Found existing comment")
            existing_comment = pr_comment

    # # Tricky here, we want everything all in one comment. So prepare a header, then append each of the comments and
    # # create a comment
    # comments_markdown = [
    #     "| Component | Vulnerability | Severity |  Policy | Description | Current Ver | Upgrade to |",
    #     "| --- | --- | --- | --- | --- | --- | --- |"
    # ]
    #
    # for comment in globals.comment_on_pr_comments:
    #     comments_markdown.append(comment)
    comments_markdown = "# Synopsys Black Duck XXXX" + "\n".join(globals.comment_on_pr_comments)

    if len(comments_markdown) > 65535:
        comments_markdown = comments_markdown[:65535]

    if existing_comment is not None:
        globals.printdebug(f"DEBUG: Update/edit existing comment for PR #{pull_number_for_sha}\n{comments_markdown}")
        # existing_comment.edit("\n".join(comments_markdown))
        existing_comment.edit(comments_markdown)
    else:
        globals.printdebug(f"DEBUG: Create new comment for PR #{pull_number_for_sha}")
        github_create_pull_request_comment(g, pr, comments_markdown)
        issue = repo.get_issue(number=pr.number)
        issue.create_comment(comments_markdown)
    return True


def github_set_commit_status(is_failure):
    if (globals.github_token is None or globals.github_repo is None or globals.github_ref is None or
            globals.github_api_url is None or globals.github_sha is None):
        print("ERROR: Cannot find GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF, GTIHUB_SHA and/or GITHUB_API_URL "
              "in the environment - are you running from a GitHub action?")
        sys.exit(1)

    globals.printdebug(f"DEBUG: Set check status for commit '{globals.github_sha}', connect to GitHub at "
                       f"{globals.github_api_url}")
    g = Github(globals.github_token, base_url=globals.github_api_url)

    globals.printdebug(f"DEBUG: Look up GitHub repo '{globals.github_repo}'")
    repo = g.get_repo(globals.github_repo)
    globals.printdebug(repo)

    if is_failure:
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
