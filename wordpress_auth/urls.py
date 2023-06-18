from django.urls import path

from . import views

urlpatterns = [
    path("login", views.wordpress_login_page, name="login"),
    path("logout", views.wordpress_logout_page, name="logout")
]
