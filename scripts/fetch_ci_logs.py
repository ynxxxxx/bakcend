import urllib.request

url = "https://api.github.com/repos/ynxxxxx/bakcend/actions/jobs/120400636946/logs"
req = urllib.request.Request(url, headers={"User-Agent": "CI-Monitor"})
try:
    with urllib.request.urlopen(req) as resp:
        content = resp.read().decode("utf-8", errors="replace")
        lines = content.splitlines()
        print("TOTAL LINES:", len(lines))
        for line in lines[-50:]:
            print(line)
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code, e.reason)
except Exception as e:
    print("Error:", e)
