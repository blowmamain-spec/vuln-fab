import os
import shlex


def handler(cursor):
    value = request.args["v"]
    open("/data/" + os.path.basename(value)).read()
