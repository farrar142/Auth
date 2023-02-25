import os
from dotenv import load_dotenv
from rest_framework import status
from accounts.schemas import TokenResponse
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
            "email": "highcolor_12@naver.com",
            "callback": "https://blog.honeycombpizza.link",
            "scheme": "https",
            "url": "blog",
        }
        resp = self.client.post("/auth/signup/email/", data)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        resp = self.client.post("/auth/signup/email/", data)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        resp = self.client.get("/users/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        email_key = find_email_key()
        resp = self.client.post("/auth/token/", {"code": email_key})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        resp = self.client.post("/auth/token/", {"code": email_key})
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


def find_email_key():
    keys: list[str] = cache.keys("*")
    email_key = list(filter(lambda x: not x.startswith("email"), keys))
    return email_key[0]
