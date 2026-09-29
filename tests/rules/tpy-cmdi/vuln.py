import os
import shlex


def handler(cursor):
    value = request.args["v"]
    os.system("ping " + value)  # vuln: tpy-cmdi
