"""simple_openid_connect_django URL Configuration

These urls should be included into your project wherever you like via::

    urlpatterns = [
        ...
        path("auth/openid/", include("simple_openid_connect_django.urls")),
    ]

"""
from django.urls import path

from simple_openid_connect_django import views

app_name = "simple_openid_connect_django"
urlpatterns = [
    path("login/", views.InitLoginView.as_view(), name="login"),
    path("login-callback/", views.LoginCallbackView.as_view(), name="login-callback"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
]
