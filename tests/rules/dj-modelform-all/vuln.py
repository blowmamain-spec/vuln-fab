from django import forms

from shop.models import Order


class OrderForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = "__all__"  # vuln: dj-modelform-all


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Order
        exclude = ["paid"]  # vuln: dj-modelform-all
