import requests

requests.get(url, verify=False)  # vuln: py-requests-verify-false
requests.post(url, data=payload, timeout=5, verify=False)  # vuln: py-requests-verify-false
