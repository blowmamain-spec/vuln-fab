import os
import shlex


def handler(cursor):
    value = request.args["v"]
    mark_safe("<b>" + escape(value) + "</b>")
