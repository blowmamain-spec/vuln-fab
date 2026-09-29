import os
import shlex


def handler(cursor):
    value = request.args["v"]
    pickle.loads(value.encode())  # vuln: tpy-deser
