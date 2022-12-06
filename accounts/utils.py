from datetime import datetime, timedelta

import jwt

from typing import TypedDict, Any

import requests

import base64
import os.path
from email.mime.text import MIMEText


from .models import User, ThirdPartyIntegration

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from rest_framework_simplejwt.tokens import RefreshToken

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


def get_credentials():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credential.json", SCOPES)
            creds = flow.run_local_server(port=8080)

        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    service = build("gmail", "v1", credentials=creds)
    return service


def send_verify_mail(to, username, verify_number):
    service = get_credentials()
    message = MIMEText(
        username + "님, 안녕하세요.<br/>"
        "메일 인증 번호는 <strong>"
        + verify_number
        + "</strong> 입니다.<br/>"
        + "이 인증을 요청하지 않았다면 이 이메일을 무시하셔도 됩니다.<br/><br/>"
        "팀 마이페이서",
        "html",
    )
    message["to"] = to
    message["from"] = "support@palzakpalzak.com"
    message["subject"] = "[마이페이서] 메일 인증 번호 입니다."
    raw_message_no_attachment = base64.urlsafe_b64encode(message.as_bytes())
    raw_message_no_attachment = raw_message_no_attachment.decode()
    body = {"raw": raw_message_no_attachment}

    try:
        service.users().messages().send(userId="me", body=body).execute()
        return True
    except Exception as e:
        print(e)
        return False


def send_password_mail(to, username, password):
    service = get_credentials()
    message = MIMEText(
        username + "님, 안녕하세요.<br/>"
        "재발급 된 비밀번호는 <strong>" + password + "</strong> 입니다.<br/><br/>"
        "팀 마이페이서",
        "html",
    )
    message["to"] = to
    message["from"] = "support@palzakpalzak.com"
    message["subject"] = "[마이페이서] 새 비밀번호를 발송해드립니다."
    raw_message_no_attachment = base64.urlsafe_b64encode(message.as_bytes())
    raw_message_no_attachment = raw_message_no_attachment.decode()
    body = {"raw": raw_message_no_attachment}

    try:
        service.users().messages().send(userId="me", body=body).execute()
        return True
    except Exception as e:
        print(e)
        return False


def refresh_thirdparty_verify():
    thirdparty_user_list = ThirdPartyIntegration.objects.all()

    for third_user in thirdparty_user_list:
        user = User.objects.get(id=third_user.user.pk)
        user.is_verified = True
        user.save()
