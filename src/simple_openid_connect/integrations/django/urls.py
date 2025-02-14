"""
simple_openid_connect URL Configuration

These urls should be included into your project wherever you like via::

    urlpatterns = [
        ...
        path("auth/openid/", include("simple_openid_connect.integrations.django.urls")),
    ]

"""

from django.urls import path

from . import views

app_name = "simple_openid_connect"
urlpatterns = [
    path("login/", views.InitLoginView.as_view(), name="login"),
    path("login-callback/", views.LoginCallbackView.as_view(), name="login-callback"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path(
        "logout/frontchannel-notify/",
        views.FrontChannelLogoutNotificationView.as_view(),
        name="logout-frontchannel-notify",
    ),
]
