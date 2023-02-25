from datetime import datetime, timedelta

import jwt

from typing import TypedDict, Any

import requests

import base64
import os.path
from email.mime.text import MIMEText


from .models import User, ThirdPartyIntegration

from googleapiclient.discovery import build
from django.core.mail import EmailMessage, send_mail

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


class KakaoProfile(TypedDict):
    nickName: str
    profileImageURL: str


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


def kakao_get_self(access_token: str) -> KakaoTokenInfo:
    """
    Kakao API를 사용하여 사용자 자신의 정보를 취득합니다.
    """
    response = requests.get(
        "https://kapi.kakao.com/v1/user/access_token_info",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    if response.status_code != 200:
        raise Exception("kakao_get_self() failed")

    return response.json()


def kakao_get_self_profile(access_token: str) -> KakaoProfile:
    """
    KakaoTalk 사용자 자신의 프로필 정보를 취득합니다
    """
    response = requests.get(
        "https://kapi.kakao.com/v1/api/talk/profile",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    if response.status_code != 200:
        raise Exception("kakao_get_self_profile() failed")

    return response.json()


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
