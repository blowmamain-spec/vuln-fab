import os


def run():
    host = request.args["host"]
    os.system("ping " + host)  # vuln: tpy-cmdi
