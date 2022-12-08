import os
import jwt
from typing import Optional, TypedDict, Literal
from django.http import HttpRequest
from django.conf import settings
from ninja import errors
from ninja.security.http import HttpBearer
from rest_framework import authentication, exceptions
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from accounts.models import User
from common_module.utils import Token

from dotenv import load_dotenv

load_dotenv()


def get_jwt_token_from_dict(data: dict):
    bearer_token: Optional[str] = data.get("HTTP_AUTHORIZATION")
    if not bearer_token:
        return False
    token = parse_bearer_token(bearer_token)
    if token:
        return token
    return False


def parse_bearer_token(token: str):
    splitted = token.split(" ")
    if not len(splitted) == 2:
        return False
    if splitted[0] != "Bearer":
        return False
    return splitted[1]


def parse_jwt(access_token: str):
    try:
        token = jwt.decode(access_token, options={"verify_signature": False})
        return Token(**token)
    except:
        return False


class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None
        token = parse_jwt(raw_token)  # type: ignore
        if not token:
            raise exceptions.AuthenticationFailed
        user = User.objects.filter(id=token.get("user_id")).first()
        if user:
            return user, str(raw_token)
        raise exceptions.AuthenticationFailed

        # return self.get_user(validated_token), validated_token

    @classmethod
    def append_token_claims(cls, refresh_token: RefreshToken, user: User):
        secret_key = settings.SECRET_KEY
        decode_jwt = jwt.decode(
            str(refresh_token.access_token), secret_key, algorithms=["HS256"]
        )
        decode_jwt["role"] = []
        # add payload here!!
        if user.is_staff or user.is_superuser:
            decode_jwt["role"].append("staff")

        # encode
        encoded = jwt.encode(decode_jwt, secret_key, algorithm="HS256")

        return {
            "status": True,
            "refresh": str(refresh_token),
            "access": str(encoded),
        }


class InternalJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None
        return parse_jwt(raw_token)  # type: ignore


class AuthBearer(HttpBearer):
    def authenticate(self, request, token: str):
        info = parse_jwt(token)
        if info:
            return info
        raise errors.AuthenticationError
