import os
import shlex


def handler(cursor):
    value = request.args["v"]
    requests.get("https://api.example.com/x", params={"q": value})
