from django.urls import path, re_path

from . import views

urlpatterns = [
    path("login/", views.wordpress_login_page_redirect, name="login"),
    #Capture url to redirect after login
    re_path("login-trapper/(?P<final_url>.*)", views.wordpress_login_trapper, name="login-trapper"),
    path("logout/", views.wordpress_logout_page_redirect, name="logout")
]
