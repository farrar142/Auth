from django.urls import include, path
from rest_framework import routers
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from .views import (
    UserViewSet,
    email_login,
    password_login,
    verify_email,
    refresh_token,
    auth_landing,
    signup_by_thirdparty,
    authenticate_by_thirdparty,
)


api_router = routers.DefaultRouter()
router = routers.DefaultRouter()

router.register("users", UserViewSet)


urlpatterns = [
    path("", include(router.urls)),
    path("auth/token/refresh", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/ping", TokenVerifyView.as_view(), name="token_ping"),
    path("auth/signin/classic", password_login),
    path("auth/signin/thirdparty", authenticate_by_thirdparty),
    path("auth/signup/thirdparty", signup_by_thirdparty),
    path("auth/signup/email", email_login),
    path("auth/token", verify_email),
    path("auth/token/refresh", refresh_token, name="token_refresh/"),
    path("auth/ping", TokenVerifyView.as_view(), name="token_ping/"),
    path("auth/landing", auth_landing),
]
