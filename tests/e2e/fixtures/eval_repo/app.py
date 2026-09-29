import os


def handler(request):
    expr = request.GET["expr"]
    return eval(expr)


class Calc:
    def run(self, text):
        # eval is dangerous
        return eval(text) + eval("1 + 1")


safe = os.getcwd()
