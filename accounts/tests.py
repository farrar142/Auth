import os
from dotenv import load_dotenv
from rest_framework import status
from base.test import TestCase

load_dotenv()

# Create your tests here.
NICKNAME = os.getenv("TEST_USER_NAME")
EMAIL = os.getenv("TEST_USER_EMAIL")
PASSWORD = os.getenv("TEST_USER_PASSWORD")


class TestUserCreate(TestCase):
    def test_url(self):
        data = {}
        data.update(email=EMAIL, password=PASSWORD, nickname=NICKNAME)
        resp = self.client.post("/auth/signup/email/", data)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        resp = self.client.get("/users/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        resp = self.client.post("/auth/token", {"email": EMAIL, "password": PASSWORD})
        print(resp.json())
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
