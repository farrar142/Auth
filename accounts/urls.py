from django.urls import include, path
from rest_framework import routers
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from .views import (
    authenticate_by_email,
    signup_by_email,
    authenticate_by_thirdparty,
    signup_by_thirdparty,
    verification_by_email,
    verification_token,
)

api_router = routers.DefaultRouter()

# urlpatterns = [
#     path("", include(api_router.urls)),
#     path("auth/signup/email", signup_by_email),
#     path("auth/signup/thirdparty", signup_by_thirdparty),
#     path("auth/verify/email", verification_by_email),
#     path("auth/verify", verification_token),
#     path("auth/token", authenticate_by_email, name="token_obtain_pair"),
#     path("auth/token/thirdparty", authenticate_by_thirdparty),
#     path("auth/token/refresh", TokenRefreshView.as_view(), name="token_refresh"),
#     path("auth/ping", TokenVerifyView.as_view(), name="token_ping"),
# ]
