detect_jar = "/tmp/synopsys-detect.jar"
# workflow_script = "/Users/mbrad/working/blackduck-scan-action/blackduck-rapid-scan-to-github.py"
# detect_jar = "./synopsys-detect.jar"
# workflow_script = "/Users/jcroall/PycharmProjects/blackduck-scan-action/blackduck-rapid-scan-to-github.py"
debug = 0
# fix_pr = ''
# upgrade_major = ''
# comment_on_pr = ''
# sarif = "blackduck-sarif.json"
# incremental_results = False
# upgrade_indirect = False
# skip_detect = False
bd = None
args = None

baseline_comp_cache = None
bdio_graph = None
bdio_projects = None
rapid_scan_data = None
detected_package_files = None
comment_on_pr_comments = []
tool_rules = []
results = []
fix_pr_data = dict()
files_to_patch = None
rscan_items = []

github_token = None
github_repo = None
github_branch = None
github_ref = None
github_api_url = None
github_sha = None


def printdebug(dstring):
    if False:
        print(dstring)