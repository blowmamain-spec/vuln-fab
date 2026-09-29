from django.utils.html import format_html
from django.utils.safestring import mark_safe


def render_name(name):
    return format_html("<b>{}</b>", name)


def static():
    return mark_safe("<hr>")
