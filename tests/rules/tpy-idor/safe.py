import os
import shlex


def handler(cursor):
    value = request.args["v"]
    owner = current_user.id
    order = Order.query.get(value)
