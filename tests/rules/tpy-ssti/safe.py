import os
import shlex


def handler(cursor):
    value = request.args["v"]
    render_template_string("Hello {{ name }}", name=value)
