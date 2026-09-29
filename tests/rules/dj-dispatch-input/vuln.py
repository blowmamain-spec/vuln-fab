import importlib

from shop import actions


def run(request):
    name = request.GET["action"]
    return getattr(actions, name)(request)  # vuln: dj-dispatch-input


def load(request):
    module = importlib.import_module(request.POST["plugin"])  # vuln: dj-dispatch-input
    return module
