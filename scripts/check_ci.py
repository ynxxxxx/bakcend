import urllib.request
import json
import sys

url = "https://api.github.com/repos/ynxxxxx/bakcend/actions/runs"
req = urllib.request.Request(url, headers={"User-Agent": "CI-Monitor", "Accept": "application/vnd.github.v3+json"})
try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        runs = data.get("workflow_runs", [])
        print(f"Total Runs Found: {len(runs)}")
        for r in runs:
            print(f"- Run #{r['run_number']} ({r['name']}): branch={r['head_branch']} status={r['status']} conclusion={r['conclusion']} url={r['html_url']}")
            if r.get('jobs_url'):
                j_req = urllib.request.Request(r['jobs_url'], headers={"User-Agent": "CI-Monitor"})
                with urllib.request.urlopen(j_req) as j_resp:
                    j_data = json.loads(j_resp.read().decode("utf-8"))
                    for job in j_data.get('jobs', []):
                        print(f"    * Job: {job['name']} -> {job['status']} / {job['conclusion']}")
except Exception as e:
    print("Error querying GitHub API:", e)
