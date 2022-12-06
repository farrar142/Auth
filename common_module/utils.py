from typing import Literal, TypedDict, Any

from django.utils.datastructures import MultiValueDict
from django.http.request import HttpRequest
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.http.request import QueryDict, HttpRequest
from django.contrib.auth.models import AnonymousUser
from rest_framework.request import Request
from accounts.models import User


class Token(TypedDict):
    token_type: Literal["refresh"]
    exp: str
    iat: int
    jti: str
    user_id: int
    role: list[Literal["staff", "creator"]]


class MockRequest(HttpRequest, Request):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "__default__"]
    user: User | AnonymousUser
    data: MultiValueDict[str, Any]
    FILES: MultiValueDict[str, InMemoryUploadedFile]
    query_params: QueryDict
