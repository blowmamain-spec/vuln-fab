from django import forms

from catalog.models import Order


class OrderForm(forms.ModelForm):
    class Meta:
        model = Order
        # @lab vuln modelform-all cwe=CWE-915 tier=A :: semua kolom bisa diisi klien
        fields = "__all__"


class NoteForm(forms.ModelForm):
    class Meta:
        model = Order
        # @lab decoy modelform-all cwe=CWE-915 :: daftar kolom eksplisit
        fields = ["note"]
