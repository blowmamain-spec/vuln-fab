from django.conf import settings
from django.db import models


class Country(models.Model):
    code = models.CharField(max_length=2)
    name = models.CharField(max_length=80)


class Order(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    total = models.IntegerField()
    note = models.TextField()
    paid = models.BooleanField(default=False)
    api_token = models.CharField(max_length=40)
