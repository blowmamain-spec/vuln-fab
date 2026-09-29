from django.urls import path

from catalog import views

urlpatterns = [
    path("search/", views.search),
    path("ping/", views.ping),
    path("ping_safe/", views.ping_safe),
    path("greet/", views.greet),
    path("greet_safe/", views.greet_safe),
    path("fetch/", views.fetch),
    path("fetch_safe/", views.fetch_safe),
    path("download/", views.download),
    path("download_safe/", views.download_safe),
    path("go/", views.go),
    path("go_safe/", views.go_safe),
    path("restore/", views.restore),
    path("orders/<int:order_id>/", views.order_detail),
    path("orders/<int:order_id>/mine/", views.order_detail_owned),
    path("countries/<int:country_id>/", views.country_detail),
    path("orders/<int:order_id>/delete/", views.order_delete),
    path("orders/<int:order_id>/archive/", views.order_archive),
    path("orders/<int:order_id>/cancel/", views.order_cancel),
    path("orders/<int:order_id>/pay/", views.order_pay),
    path("run/", views.run_action),
    path("run_safe/", views.run_action_safe),
    path("profile/", views.profile_page),
    path("profile_safe/", views.profile_page_safe),
]
