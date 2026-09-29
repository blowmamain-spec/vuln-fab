from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.urls import path
from django.views import View

from shop.models import Order


@login_required
def delete_order(request, order_id):
    Order.objects.get(pk=order_id, user=request.user).delete()
    return HttpResponse("ok")


def order_detail(request, order_id):
    if not request.user.is_authenticated:
        return HttpResponse(status=401)
    return HttpResponse(Order.objects.get(pk=order_id, user=request.user).total)


class OrderAPI(LoginRequiredMixin, View):
    def post(self, request, order_id):
        Order.objects.filter(pk=order_id, user=request.user).update(paid=True)
        return HttpResponse("ok")


def login(request):
    Order.objects.create(total=0)
    return HttpResponse("login page")


def about(request):
    return HttpResponse("about")


urlpatterns = [
    path("orders/<int:order_id>/delete/", delete_order),
    path("orders/<int:order_id>/", order_detail),
    path("orders/<int:order_id>/pay/", OrderAPI.as_view()),
    path("login/", login),
    path("about/", about),
]
