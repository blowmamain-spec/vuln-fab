import os
import shlex


def run():
    host = shlex.quote(request.args["host"])
    os.system("ping " + host)
