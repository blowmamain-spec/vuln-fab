from django.urls import path
from django.http import HttpResponse
from django.views import View

from shop.models import Order


def delete_order(request, order_id):  # vuln: dj-view-no-auth
    Order.objects.get(pk=order_id).delete()
    return HttpResponse("ok")


def order_detail(request, order_id):  # vuln: dj-view-no-auth
    order = Order.objects.get(pk=order_id)
    return HttpResponse(order.total)


class OrderAPI(View):  # vuln: dj-view-no-auth
    def post(self, request, order_id):
        Order.objects.filter(pk=order_id).update(paid=True)
        return HttpResponse("ok")


urlpatterns = [
    path("orders/<int:order_id>/delete/", delete_order),
    path("orders/<int:order_id>/", order_detail),
    path("orders/<int:order_id>/pay/", OrderAPI.as_view()),
]
