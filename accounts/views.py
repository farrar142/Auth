import datetime
import json
import logging

from io import BytesIO
from typing import Tuple, Iterable, TypedDict, Optional

import requests
import pytz
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction, IntegrityError
from django.http import HttpResponse
from django.contrib.auth.models import AnonymousUser
from django.utils.crypto import get_random_string
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


class TPInfo(TypedDict):
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


@api_view(["POST"])
@authentication_classes([])
def authenticate_by_email(request: MockRequest):
    form = AuthenticateByEmailForm(data=request.data)
    if not form.is_valid():
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    data = form.cleaned_data

    user = User.objects.filter(email=data["email"]).first()
    if not user:
        raise exceptions.AuthenticationFailed
    refresh_token = RefreshToken.for_user(user)
    claim_token = CustomJWTAuthentication.append_token_claims(refresh_token, user)
    return Response(claim_token)


def _process_thirdparty(request: Request):
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
        print(f"{access_token=}")
        response = google_get_self(access_token)
        return TPInfo(
            **{
                "id": response["email"],
                "name": response["name"],
                "profile_image_url": response["picture"],
                "is_id_email": True,
            }
        )

    if request.method != "POST":
        raise Exception("Method not allowed")

    body = json.loads(request.body.decode("utf-8"))
    auth_request_form = AuthenticateByTPForm(data=body)
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


@api_view(["POST"])
@authentication_classes([])
def authenticate_by_thirdparty(request: Request):
    (type, token, tp_info) = _process_thirdparty(request)
    print(_process_thirdparty(request))

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
    return Response(claim_token)


@api_view(["POST"])
@authentication_classes([])
def signup_by_email(request: MockRequest):
    form = SignupByEmailForm(data=request.data)
    if not form.is_valid():
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    data = form.cleaned_data
    new_user = User(
        username=data["email"],
        email=data["email"],
        nickname=data["nickname"],
    )
    new_user.set_password(data["password"])

    try:
        with transaction.atomic():
            new_user.save()
            # IntervalActivity.create_default_activity(new_user)
            # IntervalActivity.create_default_activity(new_user)
    except IntegrityError:
        # TODO: custom exception class 만들고, 이를 던지면 글로벌 핸들러가 잡아서 처리해주는건 어떨까?
        # eg) raise APIException(message='사용자가 이미 존재합니다')
        #     => HTTP 400 / body: {"is_success": true, "reason": "사용자가 이미 존재합니다"}
        #     ... 같은 식으로
        return Response(status=status.HTTP_400_BAD_REQUEST)

    return Response({"is_success": True}, status=status.HTTP_201_CREATED)


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
    nickname = tp_info["name"] if tp_info["name"] is None else username

    if type == "apple" and email.endswith("privaterelay.appleid.com"):
        # XXX: apple에서 private relay 사용 시 name은 오지 않는 듯함
        nickname = username

    if ThirdPartyIntegration.objects.filter(
        type__exact=type, identifier__exact=tp_info["id"]
    ).exists():
        return Response(status=status.HTTP_401_UNAUTHORIZED)

    new_user = User(
        username=username, email=email, nickname=nickname, bio="", is_verified=True
    )
    new_user.set_unusable_password()

    tp_integration = ThirdPartyIntegration(
        type=type, identifier=tp_info["id"], token=token
    )

    tp_integration.user = new_user

    # if tp_info["profile_image_url"] is not None:
    #     try:
    #         response = requests.get(tp_info["profile_image_url"])
    #         image_stream = BytesIO(response.content)
    #         new_user.set_profile_image_bytestream(image_stream)
    #     except Exception as e:
    #         print(e)

    try:
        with transaction.atomic():
            new_user.save()
            # IntervalActivity.create_default_activity(new_user)
            # IntervalActivity.create_default_activity(new_user)
            tp_integration.save()
    except IntegrityError:
        return Response(status=status.HTTP_400_BAD_REQUEST)

    return Response({"is_success": True})


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


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verification_token(request: MockRequest):
    user = request.user
    if isinstance(user, AnonymousUser):
        raise exceptions.AuthenticationFailed
    print(request.data)
    if user.verify_token == request.data["token"]:
        user.is_verified = True
        user.save()
        return Response({"is_success": True})
    else:
        return Response({"is_success": False})
