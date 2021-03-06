scan_utility_version = '1.0.25'
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

pkg_files = ['pom.xml', 'package.json', 'npm-shrinkwrap.json', 'package-lock.json']

pkg_exts = ['.csproj', '.fsproj', '.vbproj', '.asaproj', '.dcproj', '.shproj', '.ccproj', '.sfproj', '.njsproj',
           '.vcxproj', '.vcproj', '.xproj', '.pyproj', '.hiveproj', '.pigproj', '.jsproj', '.usqlproj', '.deployproj',
           '.msbuildproj', '.sqlproj', '.dbproj', '.rproj', '.sln']

baseline_comp_cache = None
bdio_graph = None
bdio_projects = None
rapid_scan_data = None
detected_package_files = None
comment_on_pr_comments = []
tool_rules = []
results = []
fix_pr_data = dict()
rscan_items = []

comment_on_pr_header = "Synopsys Black Duck - Vulnerabilities Reported"

github_token = ''
github_repo = ''
github_branch = ''
github_ref = ''
github_api_url = ''
github_sha = ''


def printdebug(dstring):
    if debug > 0:
        print(dstring)
