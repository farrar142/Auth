import datetime
import json
import logging

from io import BytesIO
from typing import Tuple, Iterable, TypedDict, Optional

import requests
import pytz
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction, IntegrityError, models
from django.http import HttpResponse, HttpRequest
from django.contrib.auth.models import AnonymousUser
from django.utils.crypto import get_random_string
from ninja import NinjaAPI, Schema, Field, errors
from ninja.renderers import BaseRenderer
from rest_framework import viewsets, permissions, status, generics, exceptions
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    action,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from accounts.serializers import UserReadOnlySerializer, UserUpsertSerializer
from base.authentications import CustomJWTAuthentication

from common_module.utils import MockRequest

from .models import (
    User,
    ThirdPartyIntegration,
    Relationship,
    Block,
)
from .forms import (
    AuthenticateByEmailForm,
    SignupByEmailForm,
    AuthenticateByTPForm,
    B64ProfileImageUploadForm,
)

from .utils import (
    fb_get_self,
    kakao_get_self,
    apple_get_self,
    kakao_get_self_profile,
    google_get_self,
    send_verify_mail,
    send_password_mail,
)


class MyRenderer(BaseRenderer):
    media_type = "application/json"

    def render(self, request, data, *, response_status):
        return json.dumps(data)


ninja = NinjaAPI(urls_namespace="auth", csrf=False)


class TPInfo(TypedDict):
    id: str
    name: str
    profile_image_url: str
    is_id_email: bool


class TPInfoSchema(Schema):
    id: str
    name: str
    profile_image_url: str
    is_id_email: bool


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()

    def get_serializer_class(self):
        serializer_classes = {
            "GET": UserReadOnlySerializer,
            "__default__": UserUpsertSerializer,
        }
        method = self.request.method or "GET"

        return serializer_classes.get(method, serializer_classes.get("__default__"))


class EmailLoginSchema(Schema):
    email: str
    password: str


class TokenResponse(Schema):
    refresh: str
    access: str
    status: str


# @api_view(["POST"])
# @authentication_classes([])
@ninja.post("token", response=TokenResponse)
def authenticate_by_email(request, form: EmailLoginSchema):
    email_form = AuthenticateByEmailForm(data=form.dict())
    if not email_form.is_valid():
        raise exceptions.AuthenticationFailed(detail=email_form.errors)

    data = email_form.cleaned_data

    user = User.objects.filter(email=data["email"]).first()
    if not user:
        raise exceptions.AuthenticationFailed
    refresh_token = RefreshToken.for_user(user)
    claim_token = CustomJWTAuthentication.append_token_claims(refresh_token, user)
    return claim_token


class AuthenticateByTPSchema(Schema):
    type: str
    token: str


def _process_thirdparty(form: AuthenticateByTPSchema):
    def process_facebook(access_token: str):
        response = fb_get_self(access_token)
        profile_image_url = (
            response["picture"]["data"]["url"]
            if not response["picture"]["data"]["is_silhouette"]
            else None
        )
        return TPInfo(
            **{
                "id": response["id"],
                "name": response["name"],
                "profile_image_url": profile_image_url,
                "is_id_email": False,
            }
        )

    def process_kakao(access_token: str):
        token_info = kakao_get_self(access_token)
        profile = kakao_get_self_profile(access_token)

        return TPInfo(
            **{
                "id": str(token_info["id"]),
                "name": profile["nickName"],
                "profile_image_url": profile["profileImageURL"],
                "is_id_email": False,
            }
        )

    def process_apple(access_token: str):
        response = apple_get_self(access_token)
        return TPInfo(
            **{
                "id": response["email"],
                "name": None,
                "profile_image_url": None,
                "is_id_email": True,
            }
        )

    def process_google(access_token: str):
        response = google_get_self(access_token)
        return TPInfo(
            **{
                "id": response["email"],
                "name": response["name"],
                "profile_image_url": response["picture"],
                "is_id_email": True,
            }
        )

    auth_request_form = AuthenticateByTPForm(form.dict())
    if not auth_request_form.is_valid():
        # TODO: throw custom exception
        raise Exception("form validation failed")

    auth_request = auth_request_form.cleaned_data

    type: str = auth_request["type"]
    token: str = auth_request["token"]

    if type == "kakao":
        tp_info = process_kakao(token)
    elif type == "facebook":
        tp_info = process_facebook(token)
    elif type == "apple":
        tp_info = process_apple(token)
    elif type == "google":
        tp_info = process_google(token)
    else:
        raise Exception(f"${type} is not supported yet")

    return type, token, tp_info


# @api_view(["POST"])
# @authentication_classes([])
@ninja.post("signup/thirdparty", response=TPInfoSchema)
def authenticate_by_thirdparty(request, form: AuthenticateByTPSchema):
    (type, token, tp_info) = _process_thirdparty(form)

    tp_integration: Optional[
        ThirdPartyIntegration
    ] = ThirdPartyIntegration.objects.filter(
        type__exact=type, identifier__exact=tp_info["id"]
    ).first()
    if tp_integration is None:
        raise exceptions.AuthenticationFailed
    refresh_token = RefreshToken.for_user(tp_integration.user)
    claim_token = CustomJWTAuthentication.append_token_claims(
        refresh_token, tp_integration.user
    )
    return claim_token


class SimpleResponseSchema(Schema):
    is_success: bool


class SignUpByEmailSchema(Schema):
    email: str
    password: str
    nickname: str


# @api_view(["POST"])
# @authentication_classes([])
@ninja.post("signup/email/", response={201: SimpleResponseSchema})
def signup_by_email(request, form: SignUpByEmailSchema):
    signup_form = SignupByEmailForm(data=form.dict())
    if not signup_form.is_valid():
        raise errors.AuthenticationError
    already = User.objects.filter(
        models.Q(username=form.nickname) | models.Q(email=form.email)
    )
    if already.exists():
        raise errors.AuthenticationError

    data = signup_form.cleaned_data
    new_user = User(
        username=data["email"],
        email=data["email"],
        nickname=data["nickname"],
    )
    new_user.set_password(data["password"])

    try:
        with transaction.atomic():
            new_user.save()
    except:
        raise

    return 201, {"is_success": True}


@ninja.post("signup/thirdparty", response=SimpleResponseSchema)
def signup_by_thirdparty(request, form: AuthenticateByTPSchema):
    def get_dummy_email(type: str, tp_user_id: str):
        return f"{tp_user_id}@{type}.com"

    def extract_username_from_email(email: str):
        return email.split("@")[0]

    (type, token, tp_info) = _process_thirdparty(form)
    email = (
        tp_info["id"]
        if tp_info["is_id_email"]
        else get_dummy_email(type, tp_info["id"])
    )
    username = f'{type}_{extract_username_from_email(tp_info["id"])}'
    nickname = tp_info["name"] if tp_info["name"] is None else username

    if type == "apple" and email.endswith("privaterelay.appleid.com"):
        # XXX: apple에서 private relay 사용 시 name은 오지 않는 듯함
        nickname = username

    if ThirdPartyIntegration.objects.filter(
        type__exact=type, identifier__exact=tp_info["id"]
    ).exists():
        raise errors.AuthenticationError

    new_user = User(
        username=username, email=email, nickname=nickname, bio="", is_verified=True
    )
    new_user.set_unusable_password()

    tp_integration = ThirdPartyIntegration(
        type=type, identifier=tp_info["id"], token=token
    )

    tp_integration.user = new_user

    try:
        with transaction.atomic():
            new_user.save()
            tp_integration.save()
    except IntegrityError:
        raise errors.AuthenticationError

    return {"is_success": True}


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verification_by_email(request: Request):
    user: User = request.user
    token = get_random_string(length=6)
    user.set_verify_token(token)

    is_send = send_verify_mail(user.email, user.nickname, user.verify_token)

    if is_send:
        user.save()
        return Response(status=status.HTTP_200_OK)
    else:
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
