import datetime
import json
import logging
from io import BytesIO
from typing import Iterable, Optional, Tuple, TypedDict

import uuid
from django.contrib.auth.models import AnonymousUser
from django.core.files.uploadedfile import UploadedFile
from django.db import IntegrityError, models, transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.utils.crypto import get_random_string
from ninja import NinjaAPI, Schema, errors
from ninja.renderers import BaseRenderer
from rest_framework import exceptions, generics, permissions, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.serializers import UserReadOnlySerializer, UserUpsertSerializer
from base.authentications import AuthBearer, CustomJWTAuthentication
from common_module.utils import MockRequest
from common_module.views import DisallowEditOtherUsersResourceMixin
from .schemas import *
from .forms import (
    AuthenticateByEmailForm,
    AuthenticateByPasswordForm,
    AuthenticateByTPForm,
    SignupByEmailForm,
    EmailVerifyForm,
    RefreshTokenForm,
)
from .models import ThirdPartyIntegration, User
from .utils import (
    apple_get_self,
    fb_get_self,
    google_get_self,
    kakao_get_self,
    kakao_get_self_profile,
    get_random_nums,
)
from .tasks import send_verify_mail
from .verify_storages import EmailVerifyStorage


class UserViewSet(DisallowEditOtherUsersResourceMixin, viewsets.ModelViewSet):
    queryset = User.objects.all()

    def get_serializer_class(self):
        serializer_classes = {
            "GET": UserReadOnlySerializer,
            "__default__": UserUpsertSerializer,
        }
        method = self.request.method or "GET"

        return serializer_classes.get(method, serializer_classes.get("__default__"))

    def create(self, request, *args, **kwargs):
        raise exceptions.NotAcceptable


class AuthenticateByTPSchema(Schema):
    type: str
    token: str


@api_view(["POST"])
@permission_classes([])
def password_login(request: MockRequest):
    form = AuthenticateByPasswordForm(request.data)
    if not form.is_valid():
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
    data = form.cleaned_data
    email = data["email"]
    user = (
        User.objects.annotate(tp=models.F("tp_integrations"))
        .filter(email=email, tp__isnull=True)
        .first()
    )
    if not user:
        raise exceptions.ValidationError(detail={"auth": ["계정이 존재하지 않습니다."]})
    if not user.check_password(data["password"]):
        raise exceptions.ValidationError(detail={"auth": ["비밀번호가 일치하지 않습니다."]})

    refresh_token = RefreshToken.for_user(user)
    claim_token = CustomJWTAuthentication.append_token_claims(refresh_token, user)
    return Response(claim_token)


@api_view(["POST"])
@permission_classes([])
def email_login(request: MockRequest):
    form = AuthenticateByEmailForm(request.data)
    if not form.is_valid():
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
    data = form.cleaned_data
    email = data["email"]
    username = email.split("@")[0] + "#" + "".join(get_random_nums())
    user = (
        User.objects.annotate(tp=models.F("tp_integrations"))
        .filter(email=email, tp__isnull=True)
        .first()
    )
    if not user:
        user = User(email=email, username=username, nickname=username)
        user.save()
        user_id = user.pk
        if not user_id:
            raise ConflictException(detail={"user": ["트랜젝션 오류 백엔드에게 문의하세요"]})
    storage = EmailVerifyStorage()
    if storage.get_email_term(user):
        raise exceptions.ValidationError(
            detail={"email": ["이메일을 발신한 지 3분이 지나지 않았습니다."]}
        )
    code = storage.set(user)
    storage.set_email_term(user)
    send_verify_mail.delay(user.pk, data, code)
    return Response({}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([])
def verify_email(request: MockRequest):
    form = EmailVerifyForm(request.data)
    if not form.is_valid():
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
    data = form.cleaned_data
    code: str = data["code"]
    storage = EmailVerifyStorage()
    user = storage.get(code)
    if not user:
        raise exceptions.ValidationError(detail={"code": ["유효하지 않은 코드입니다"]})
    if not user.is_verified:
        user.is_verified = True
        user.save()
    storage.drop_email_term(user)
    refresh_token = RefreshToken.for_user(user)
    claim_token = CustomJWTAuthentication.append_token_claims(refresh_token, user)
    return Response(claim_token)


@api_view(["POST"])
@permission_classes([])
def refresh_token(request: MockRequest):
    form = RefreshTokenForm(request.data)
    if not form.is_valid():
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)
    token: str = form.cleaned_data["refresh"]
    try:
        refresh_token = RefreshToken(token)
    except:
        raise exceptions.AuthenticationFailed
    claim_token = CustomJWTAuthentication.append_token_claims(refresh_token)
    return Response(claim_token)


class ConflictException(exceptions.APIException):
    status_code = exceptions.status.HTTP_409_CONFLICT
    default_detail = {"not_implemented": ["정의되지 않은 오류입니다. 백엔드 개발자에게 에러내용을 추가해 달라고하세요"]}


def auth_landing(request: HttpRequest):
    print(f"{request.GET=}")
    code = request.GET["code"]
    scheme = request.GET["scheme"]
    url = request.GET["url"]
    storage = EmailVerifyStorage()
    user = storage.get(code)
    if not user:
        return render(request, "accounts/404.html")
    storage.drop_email_term(user)
    refresh_token = RefreshToken.for_user(user)
    claim_token = CustomJWTAuthentication.append_token_claims(refresh_token, user)
    print({**request.GET})
    return render(
        request, "accounts/landing.html", {**claim_token, "scheme": scheme, "url": url}
    )
