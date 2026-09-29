from shop.models import Order


def search(name):
    a = Order.objects.raw("SELECT * FROM shop_order WHERE name = %s", [name])
    b = Order.objects.raw("SELECT * FROM shop_order")
    c = Order.objects.extra(where=["name = %s"], params=[name])
    return a, b, c
