def run(code):
    exec(code)  # vuln: py-exec


def run2(a, b):
    exec(a + b)  # vuln: py-exec
