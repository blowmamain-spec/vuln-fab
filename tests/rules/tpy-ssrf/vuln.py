import os
import shlex


def handler(cursor):
    value = request.args["v"]
    requests.get(value, timeout=3)  # vuln: tpy-ssrf
