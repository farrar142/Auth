from dataclasses import fields
from datetime import datetime, timedelta

import jwt

from typing import Literal, Optional, TypedDict, Any

import requests

import base64
import os.path
import os as env
from email.mime.text import MIMEText

from rest_framework import exceptions

from .models import User, ThirdPartyIntegration

from django.core.mail import EmailMessage
from dotenv import load_dotenv

load_dotenv()

SCOPES = ["https://www.googleapis.com/auth/gmail.send", "https://mail.google.com/"]


class FBUserPicture(TypedDict):
    width: int
    height: int
    url: str
    is_silhouette: bool


class FBUserPictureContainer(TypedDict):
    data: FBUserPicture


class FBUser(TypedDict):
    id: str
    name: str
    picture: FBUserPictureContainer


class KakaoTokenInfo(TypedDict):
    id: int
    expires_in: int
    app_id: int


class KakaoCodeAuthorization(TypedDict):
    access_token: str
    token_type: Literal["bearer"]
    refresh_token: str
    expires_in: int
    refresh_token_expires_in: int


class KakaoProfile(TypedDict):
    nickname: str
    profile_image_url: str
    thumbnail_image_url: str


class KakaoAccount(TypedDict):
    id: int
    has_email: bool
    profile: KakaoProfile


class KakaoAccountEmail(TypedDict):
    id: int
    email: str
    has_email: bool
    profile: KakaoProfile


class AppleTokenInfo(TypedDict):
    email: str
    exp: int
    sub: str


class GoogleTokenInfo(TypedDict):
    email: str
    exp: int
    sub: str
    name: str
    picture: str


def fb_get_self(access_token: str) -> FBUser:
    """
    Facebook Graph API의 /me를 호출하여 사용자 자신의 정보를 취득합니다.
    """
    response = requests.get(
        "https://graph.facebook.com/me",
        {
            "access_token": access_token,
            "fields": "id,email,name,picture",
        },
    )

    if response.status_code != 200:
        raise Exception("fb_get_self() failed")

    return response.json()


KAKAO_REST_API_KEY = env.getenv("KAKAO_REST_API_KEY", "")
KAKAO_REDIRECT_URI = env.getenv("KAKAO_REDIRECT_URI", "")


def kakao_authorize(code: str):
    endpoint = "https://kauth.kakao.com/oauth/token"
    args = {}
    args.update(grant_type="authorization_code")
    args.update(client_id=KAKAO_REST_API_KEY)
    args.update(redirect_uri=KAKAO_REDIRECT_URI)
    args.update(code=code)
    resp = requests.get(endpoint, args)
    if resp.status_code != 200:
        raise exceptions.ValidationError(
            detail={resp.json()["error"]: resp.json()["error_description"]}
        )
    return KakaoCodeAuthorization(**resp.json())


def kakao_get_self_profile(code: str) -> KakaoAccountEmail:
    """
    KakaoTalk 사용자 자신의 프로필 정보를 취득합니다
    """
    token = kakao_authorize(code)
    response = requests.get(
        "https://kapi.kakao.com/v2/user/me",
        # data={"scopes": ["profile_nickname", "profile_image", "account_email"]},
        headers={"Authorization": f"Bearer {token['access_token']}"},
    )
    if response.status_code != 200:
        raise Exception("kakao_get_self_profile() failed")
    json = response.json()
    arranged = {**json.get("kakao_account"), "id": json.get("id")}
    info = KakaoAccount(**arranged)
    from pprint import pprint

    pprint(info)
    dummy_email = str(info["id"]) + "@kakao.com"
    return KakaoAccountEmail(email=dummy_email, **info)


def apple_get_self(access_token: str):
    """
    Apple에서 사용자 정보를 호출합니다.
    """

    decrypt: AppleTokenInfo = AppleTokenInfo(
        **jwt.decode(access_token, options={"verify_signature": False})
    )
    return decrypt


def google_get_self(access_token: str):
    """
    Google에서 사용자 정보를 호출합니다.
    """
    decrypt: GoogleTokenInfo = GoogleTokenInfo(
        **jwt.decode(access_token, options={"verify_signature": False})
    )

    return decrypt


def send_verify_mail(to, username, verify_number):
    message = (
        username + "님, 안녕하세요.<br/>"
        "메일 인증 번호는 <strong>"
        + verify_number
        + "</strong> 입니다.<br/>"
        + "이 인증을 요청하지 않았다면 이 이메일을 무시하셔도 됩니다.<br/><br/>"
    )

    emailObject = EmailMessage("블로그 메일 인증 번호 입니다.", message, to=[to])
    emailObject.content_subtype = "html"
    result = emailObject.send()


def refresh_thirdparty_verify():
    thirdparty_user_list = ThirdPartyIntegration.objects.all()

    for third_user in thirdparty_user_list:
        user = User.objects.get(id=third_user.user.pk)
        user.is_verified = True
        user.save()


def get_random_nums(length: int = 4):
    import random

    return [
        random.choice(list(map(lambda x: str(x), range(10)))) for x in range(length)
    ]
