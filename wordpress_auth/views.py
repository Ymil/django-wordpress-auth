from django.http import HttpResponse, HttpResponseForbidden

from wordpress_auth.decorators import (
    wordpress_login_required, wordpress_requires_role,
    wordpress_requires_capability
)

from django.shortcuts import redirect
from wordpress_auth.utils import get_login_url, get_logout_url, get_wordpress_user

from django.contrib.auth import login, logout
from django.contrib.auth import get_user_model
User = get_user_model()
from django.urls import reverse

def wordpress_login_page_redirect(request):
    final_url = request.build_absolute_uri(request.GET.get('next', '/'))
    redirect_to = request.build_absolute_uri(reverse("login-trapper", kwargs={'final_url': final_url}))
    return redirect(get_login_url() + "?redirect_to=" + redirect_to)


def wordpress_login_trapper(request, final_url):
    wordpress_user = get_wordpress_user(request)
    if wordpress_user:
        django_user = User.objects.get(pk=wordpress_user.id)
        login(request, django_user)
        return redirect(final_url)
    else:
        # response access denied code django
        return HttpResponseForbidden('Access denied')
        # return HttpResponse('Error al iniciar sesión')
    

def wordpress_logout_page_redirect(request):
    logout(request)
    return redirect(get_logout_url())

@wordpress_login_required
def show_session(request):
    return HttpResponse(request.wordpress_user.login)


@wordpress_requires_role('lima_member')
def test_roles(request):
    return HttpResponse('Success')


@wordpress_requires_capability('view_cls_records')
def test_capabilities(request):
    return HttpResponse('Success')
