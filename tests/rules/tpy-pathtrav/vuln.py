import os
import shlex


def handler(cursor):
    value = request.args["v"]
    open("/data/" + value).read()  # vuln: tpy-pathtrav
