from django.http import HttpResponse
from django.urls import path

from shop.models import Order


def pay(request, order_id):
    Order.objects.filter(pk=order_id, user=request.user).update(paid=True)
    return HttpResponse("ok")


urlpatterns = [path("pay/<int:order_id>/", pay)]
