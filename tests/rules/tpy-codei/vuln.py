import os
import shlex


def handler(cursor):
    value = request.args["v"]
    eval(value)  # vuln: tpy-codei
