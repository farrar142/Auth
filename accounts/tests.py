import os
from dotenv import load_dotenv
from rest_framework import status
from accounts.models import User
from accounts.schemas import TokenResponse
from accounts.tasks import send_verify_mail
from base.test import TestCase
from django.core.cache import cache

load_dotenv()

# Create your tests here.
NICKNAME = os.getenv("TEST_USER_NAME")
EMAIL = os.getenv("TEST_USER_EMAIL")
PASSWORD = os.getenv("TEST_USER_PASSWORD")


class TestUserCreate(TestCase):
    def test_url(self):
        data = {
            "email": "gksdjf1690@gmail.com",
            "callback": "http://localhost:10001/auth/landing/",
            "scheme": "https",
            "url": "blog",
        }
        resp = self.client.post("/auth/signup/email", data)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        resp = self.client.post("/auth/signup/email", data)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        resp = self.client.get("/users/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        email_key = find_email_key()
        resp = self.client.post("/auth/token", {"code": email_key})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        resp = self.client.post("/auth/token", {"code": email_key})
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        send_verify_mail.delay(1, data, "fffff")


def find_email_key():
    keys: list[str] = cache.keys("*")
    email_key = list(filter(lambda x: not x.startswith("email"), keys))
    return email_key[0]


class TestKakaoLogin(TestCase):
    def test_kakao_authorize(self):
        token = "D08KpOibeAc7yw07ERq-UOCewCPnup2KCAxkg-_7NCGZIo6jD-ukOptRmLHDCsRzMzcf9worDSAAAAGGqIQPLA"
        from accounts.utils import kakao_get_self_profile

        resp = self.client.get("/users/")
        self.assertEqual("next" in resp.json().keys(), True)
        self.client.login(self.user)
        resp = self.client.get("/users/me/")
        print(resp.json())
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        # resp = self.client.post(
        #     "/auth/signup/thirdparty", {"type": "kakao", "token": token}
        # )
        # print(resp.json())

        # resp = self.client.post(
        #     "/auth/signin/thirdparty", {"type": "kakao", "token": token}
        # )
        # print(resp.json())
