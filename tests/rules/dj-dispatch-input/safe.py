from shop import actions

ALLOWED = {"list": actions.list_items, "show": actions.show_item}


def run(request):
    handler = ALLOWED.get(request.GET["action"])
    return handler(request) if handler else None


def named(request):
    name = request.GET["action"]
    if not name.isalnum():
        return None
    return getattr(actions, name)(request)
