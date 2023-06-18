from django.http import HttpResponse

from wordpress_auth.decorators import (
    wordpress_login_required, wordpress_requires_role,
    wordpress_requires_capability
)

from django.shortcuts import redirect
from wordpress_auth.utils import get_login_url, get_logout_url

def wordpress_login_page(request):
    redirect_to = request.build_absolute_uri(request.path)
    return redirect(get_login_url() + "?redirect_to=" + redirect_to)

def wordpress_logout_page(request):
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
