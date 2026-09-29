import os
import shlex


def handler(cursor):
    value = request.args["v"]
    order = Order.query.get(value)  # vuln: tpy-idor
