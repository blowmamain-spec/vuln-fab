from shop.models import Order


def search(name):
    a = Order.objects.raw("SELECT * FROM shop_order WHERE name = '%s'" % name)  # vuln: dj-sql-raw
    b = Order.objects.raw(f"SELECT * FROM shop_order WHERE name = '{name}'")  # vuln: dj-sql-raw
    c = Order.objects.extra(where=["name = '" + name + "'"])  # vuln: dj-sql-raw
    return a, b, c
