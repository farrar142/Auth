import os
import json
import requests
from typing import Any, Callable, Literal

from django.http.response import HttpResponse

from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import User


def request_wrapper(func: Callable[..., Any]):
    def helper(*args, **kwargs) -> HttpResponse:
        return func(*args, **kwargs)

    return helper


class Client(APIClient):
    def login_with_token(self, token: str):
        self.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    def login(self, user):
        token = str(RefreshToken.for_user(user).access_token)
        self.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    def wrong_login(self):
        self.credentials(HTTP_AUTHORIZATION="Bearer dawdawdw")

    def logout(self):
        self.credentials()

    @request_wrapper
    def get(
        self, path, data=None, follow=False, content_type="application/json", **extra
    ):
        response = super(Client, self).get(path, data=data, **extra)
        return response

    @request_wrapper
    def post(
        self,
        path,
        data=None,
        format=None,
        content_type="application/json",
        follow=False,
        **extra,
    ):
        if content_type == "application/json":
            data = json.dumps(data)
        return super(Client, self).post(
            path, data, format, content_type, follow, **extra
        )

    @request_wrapper
    def patch(
        self,
        path,
        data=None,
        format=None,
        content_type="application/json",
        follow=False,
        **extra,
    ):
        if content_type == "application/json":
            data = json.dumps(data)
        return super(Client, self).patch(
            path,
            data,
            format,
            content_type,
            follow,
            **extra,
        )

    @request_wrapper
    def delete(
        self,
        path,
        data=None,
        format=None,
        content_type="application/json",
        follow=False,
        **extra,
    ):
        if content_type == "application/json":
            data = json.dumps(data)
        return super(Client, self).delete(
            path,
            data,
            format,
            content_type,
            follow,
            **extra,
        )


class TestCase(APITestCase):
    client_class = Client
    client: Client
    user: User
    user2: User
    admin: User
    creator: User
    creator2: User

    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create(
            username="testuser",
            email="testuser@contoso.net",
            nickname="테스트 사용자",
        )
        self.user.set_password("test1234!@#$")
        self.user.save()
        self.user2 = User.objects.create(
            username="테스트유저",
            email="testuser2@contoso.net",
            nickname="테스트 사용자2",
        )
        self.user2.set_password("test1234!@#$2")
        self.user2.save()
        self.admin = User.objects.create(
            username="admin",
            email="admin2@contoso.net",
            nickname="어드민 사용자2",
            is_staff=True,
        )
