from django import forms

from shop.models import Order


class OrderForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = ["note", "address"]


def filtered(qs):
    return qs.exclude(paid=True)
