import os
import shlex


def handler(cursor):
    value = request.args["v"]
    eval(str(int(value)))
