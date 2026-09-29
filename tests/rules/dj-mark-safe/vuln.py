from django.utils.safestring import mark_safe


def render_name(name):
    return mark_safe("<b>" + name + "</b>")  # vuln: dj-mark-safe


def render_f(name):
    return mark_safe(f"<i>{name}</i>")  # vuln: dj-mark-safe
