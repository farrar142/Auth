import requests
import json
from io import BytesIO
from typing import Iterable, Optional, Tuple, TypedDict

import uuid
from django.contrib.auth.models import AnonymousUser
from django.core.files.uploadedfile import UploadedFile
from django.db import IntegrityError, models, transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.utils.crypto import get_random_string
from rest_framework import exceptions, generics, permissions, status, viewsets
from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
    action,
)
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
    kakao_get_self_profile,
    get_random_nums,
)
from .tasks import send_verify_mail
from .verify_storages import EmailVerifyStorage


class UserViewSet(DisallowEditOtherUsersResourceMixin, viewsets.ModelViewSet):
    queryset = User.objects.all()
    lookup_value_regex = r"me|\d+"
    ordering = ("-id",)

    def get_serializer_class(self):
        serializer_classes = {
            "GET": UserReadOnlySerializer,
            "__default__": UserUpsertSerializer,
        }
        method = self.request.method or "GET"

        return serializer_classes.get(method, serializer_classes.get("__default__"))

    def create(self, request, *args, **kwargs):
        raise exceptions.NotAcceptable

    @action(methods=["GET"], detail=False, url_path="me")
    def my_info(self, *args, **kwargs):
        if isinstance(self.request.user, AnonymousUser):
            raise exceptions.NotAuthenticated
        serializer = UserReadOnlySerializer(instance=self.request.user)
        return Response(data=serializer.data)

    @action(methods=["GET"], detail=False, url_path="find_by_name/(?P<username>\w+)")
    def get_blog_of_user(self, *args, **kwargs):
        username = kwargs["username"]
        user = User.objects.filter(username=username).first()
        if not user:
            raise exceptions.NotFound
        serializer = self.get_serializer(instance=user)
        return Response(serializer.data)


def _process_thirdparty(request: Request) -> Tuple[str, str, TPInfo]:
    def process_facebook(access_token: str) -> TPInfo:
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

    def process_kakao(access_token: str) -> TPInfo:
        # token_info = kakao_get_self(access_token)
        response = kakao_get_self_profile(access_token)
        return TPInfo(
            **{
                "id": response["email"],
                "name": response["profile"]["nickname"],
                "profile_image_url": response["profile"]["profile_image_url"],
                "is_id_email": True,
            }
        )

    def process_apple(access_token: str) -> TPInfo:
        response = apple_get_self(access_token)
        return TPInfo(
            **{
                "id": response["email"],
                "name": None,
                "profile_image_url": None,
                "is_id_email": True,
            }
        )

    def process_google(access_token: str) -> TPInfo:
        response = google_get_self(access_token)
        return {
            "id": response["email"],
            "name": response["name"],
            "profile_image_url": response["picture"],
            "is_id_email": True,
        }

    if request.method != "POST":
        raise Exception("Method not allowed")

    body = json.loads(request.body.decode("utf-8"))
    auth_request_form = AuthenticateByTPForm(data=body)
    auth_request_form.is_valid(raise_exception=True)
    auth_request = auth_request_form.validated_data

    type = auth_request["type"]
    token = auth_request["token"]
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


@api_view(["POST"])
@authentication_classes([])
def signup_by_thirdparty(request: Request):
    def get_dummy_email(type: str, tp_user_id: str):
        return f"{tp_user_id}@{type}.com"

    def extract_username_from_email(email: str) -> str:
        return email.split("@")[0]

    (type, token, tp_info) = _process_thirdparty(request)
    email = (
        tp_info["id"]
        if tp_info["is_id_email"]
        else get_dummy_email(type, tp_info["id"])
    )
    username = f'{type}_{extract_username_from_email(tp_info["id"])}'
    nickname = tp_info.get("name", username) or username
    username = username + "#" + "".join(get_random_nums(4))
    if type == "apple" and email.endswith("privaterelay.appleid.com"):
        # XXX: apple에서 private relay 사용 시 name은 오지 않는 듯함
        nickname = username
    if ThirdPartyIntegration.objects.filter(
        type__exact=type, identifier__exact=tp_info["id"]
    ).exists():
        raise exceptions.ValidationError(
            detail={"user": [f"{email}로 가입된 계정이 이미 존재합니다."]}
        )
    new_user = User(username=username, email=email, nickname=nickname, is_verified=True)
    user_dict = {}
    user_dict.update(
        username=username,
        email=email,
        nickname=nickname,
        bio="",
        is_verified=True,
        type=type,
        identifier=tp_info["id"],
        token=token,
    )
    new_user.set_unusable_password()
    tp_integration = ThirdPartyIntegration(
        type=type, identifier=tp_info["id"], token=token
    )
    tp_integration.user = new_user

    if tp_info["profile_image_url"] is not None:
        try:
            response = requests.get(tp_info["profile_image_url"])
            image_stream = BytesIO(response.content)
        except Exception as e:
            print(e)

    try:
        with transaction.atomic():
            new_user.save()
            tp_integration.save()
    except IntegrityError:
        return Response(
            {"user": ["데이터 저장중에 문제가 생겼습니다."]}, status=status.HTTP_400_BAD_REQUEST
        )

    return Response({"is_success": True})


@api_view(["POST"])
@authentication_classes([])
def authenticate_by_thirdparty(request: MockRequest):
    (type, token, tp_info) = _process_thirdparty(request)

    tp_integration: Optional[
        ThirdPartyIntegration
    ] = ThirdPartyIntegration.objects.filter(
        type__exact=type, identifier__exact=tp_info["id"]
    ).first()
    if tp_integration == None:
        return Response(
            {"auth": [f"{type} 으로 가입된 유저가 없습니다."]}, status=status.HTTP_401_UNAUTHORIZED
        )
        # raise exceptions.AuthenticationFailed(
        #     detail={"auth": [f"{type} 으로 가입된 유저가 없습니다."]}
        # )

    refresh_token = RefreshToken.for_user(tp_integration.user)
    claim_token = CustomJWTAuthentication.append_token_claims(refresh_token)
    return Response(claim_token)
