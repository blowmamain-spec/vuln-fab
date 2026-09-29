import os
import pickle
import shlex

import requests
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.html import escape
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt

from catalog import actions
from catalog.models import Country, Order


def search(request):
    term = request.GET.get("q", "")
    with connection.cursor() as cursor:
        # @lab vuln sqli cwe=CWE-89 tier=A :: input GET digabung ke SQL
        cursor.execute("SELECT id FROM catalog_order WHERE note = '" + term + "'")
        rows = cursor.fetchall()
    return HttpResponse(str(rows))


def search_safe(request):
    term = request.GET.get("q", "")
    with connection.cursor() as cursor:
        # @lab decoy sqli cwe=CWE-89 :: query berparameter
        cursor.execute("SELECT id FROM catalog_order WHERE note = %s", [term])
        rows = cursor.fetchall()
    return HttpResponse(str(rows))


def ping(request):
    host = request.GET["host"]
    # @lab vuln cmd-injection cwe=CWE-78 tier=A :: input GET masuk ke shell
    os.system("ping -c 1 " + host)
    return HttpResponse("ok")


def ping_safe(request):
    host = shlex.quote(request.GET["host"])
    # @lab decoy cmd-injection cwe=CWE-78 :: argumen di-quote
    os.system("ping -c 1 " + host)
    return HttpResponse("ok")


def greet(request):
    name = request.GET.get("name", "")
    # @lab vuln xss cwe=CWE-79 tier=A :: input GET ditandai aman
    return HttpResponse(mark_safe("<b>Hello " + name + "</b>"))


def greet_safe(request):
    name = request.GET.get("name", "")
    # @lab decoy xss cwe=CWE-79 :: input di-escape dulu
    return HttpResponse(mark_safe("<b>Hello " + escape(name) + "</b>"))


def fetch(request):
    url = request.GET["url"]
    # @lab vuln ssrf cwe=CWE-918 tier=A :: URL dari klien diminta server
    body = requests.get(url, timeout=3).text
    return HttpResponse(body)


def fetch_safe(request):
    city = request.GET["city"]
    # @lab decoy ssrf cwe=CWE-918 :: host tetap, input hanya parameter
    body = requests.get("https://api.example.com/weather", params={"city": city}, timeout=3).text
    return HttpResponse(body)


def download(request):
    name = request.GET["file"]
    # @lab vuln path-traversal cwe=CWE-22 tier=A :: nama berkas dari klien
    with open("/srv/files/" + name, "rb") as handle:
        return HttpResponse(handle.read())


def download_safe(request):
    name = os.path.basename(request.GET["file"])
    # @lab decoy path-traversal cwe=CWE-22 :: hanya nama dasar
    with open("/srv/files/" + name, "rb") as handle:
        return HttpResponse(handle.read())


def go(request):
    target = request.GET["next"]
    # @lab vuln redirect cwe=CWE-601 tier=A :: redirect ke URL dari klien
    return redirect(target)


def go_safe(request):
    target = request.GET["next"]
    if not url_has_allowed_host_and_scheme(target, allowed_hosts=None):
        target = "/"
    # @lab decoy redirect cwe=CWE-601 :: URL divalidasi
    return redirect(target)


def restore(request):
    blob = request.POST["state"]
    # @lab vuln deserialization cwe=CWE-502 tier=A :: pickle atas data klien
    state = pickle.loads(blob.encode("latin-1"))
    return HttpResponse(str(state))


@login_required
def order_detail(request, order_id):
    # @lab vuln idor cwe=CWE-639 tier=B :: pesanan diambil dari id URL tanpa cek pemilik
    order = Order.objects.get(pk=order_id)
    return HttpResponse(order.total)


@login_required
def order_detail_owned(request, order_id):
    # @lab decoy idor cwe=CWE-639 :: dibatasi ke pemilik
    order = get_object_or_404(Order, pk=order_id, user=request.user)
    return HttpResponse(order.total)


@login_required
def country_detail(request, country_id):
    # @lab decoy idor cwe=CWE-639 :: data referensi bersama, tanpa pemilik
    country = Country.objects.get(pk=country_id)
    return HttpResponse(country.name)


# @lab vuln view-no-auth cwe=CWE-306 tier=A :: menghapus data tanpa login
def order_delete(request, order_id):
    Order.objects.filter(pk=order_id).delete()
    return HttpResponse("deleted")


@login_required
def order_archive(request, order_id):
    # @lab decoy view-no-auth cwe=CWE-306 :: butuh login
    Order.objects.filter(pk=order_id, user=request.user).update(note="archived")
    return HttpResponse("ok")


# @lab decoy view-no-auth cwe=CWE-306 :: cek pengguna di dalam view
def order_cancel(request, order_id):
    if not request.user.is_authenticated:
        return HttpResponse(status=401)
    Order.objects.filter(pk=order_id, user=request.user).update(note="cancelled")
    return HttpResponse("ok")


@csrf_exempt
# @lab vuln csrf-exempt cwe=CWE-352 tier=A :: mengubah data tanpa CSRF
def order_pay(request, order_id):
    if request.user.is_authenticated:
        Order.objects.filter(pk=order_id, user=request.user).update(paid=True)
    return HttpResponse("ok")


def run_action(request):
    name = request.GET["action"]
    # @lab vuln dispatch-input cwe=CWE-470 tier=A :: klien memilih atribut yang dipanggil
    return getattr(actions, name)(request)


def run_action_safe(request):
    handlers = {"list": actions.list_items, "show": actions.show_item}
    handler = handlers.get(request.GET["action"])
    # @lab decoy dispatch-input cwe=CWE-470 :: daftar putih lewat dict
    return handler(request) if handler else HttpResponse(status=404)


def profile_page(request):
    return render(request, "catalog/profile.html", {"bio": request.GET.get("bio", "")})


def profile_page_safe(request):
    return render(request, "catalog/profile_safe.html", {"bio": request.GET.get("bio", "")})

