from django.http import HttpResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from shop.models import Order


@csrf_exempt
def pay(request, order_id):  # vuln: dj-csrf-exempt
    Order.objects.filter(pk=order_id).update(paid=True)
    return HttpResponse("ok")


urlpatterns = [path("pay/<int:order_id>/", pay)]
