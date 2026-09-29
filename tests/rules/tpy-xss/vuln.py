import os
import shlex


def handler(cursor):
    value = request.args["v"]
    mark_safe("<b>" + value + "</b>")  # vuln: tpy-xss
