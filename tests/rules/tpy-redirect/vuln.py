import os
import shlex


def handler(cursor):
    value = request.args["v"]
    redirect(value)  # vuln: tpy-redirect
