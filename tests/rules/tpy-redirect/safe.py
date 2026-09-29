import os
import shlex


def handler(cursor):
    value = request.args["v"]
    redirect(url_for("home", q=value))
