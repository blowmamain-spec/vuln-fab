def handler(request):
    expr = request.GET["expr"]
    return eval(expr)  # vuln: py-eval


def calc(a, b):
    return eval(a + b)  # vuln: py-eval


class C:
    def run(self, text):
        return eval(text)  # vuln: py-eval
