from ninja import Schema
from typing import TypedDict


class TPInfo(TypedDict):
    id: str
    name: str
    profile_image_url: str
    is_id_email: bool


class TPInfoSchema(Schema):
    id: str
    name: str
    profile_image_url: str
    is_id_email: bool


class EmailLoginSchema(Schema):
    email: str
    password: str


class TokenResponse(Schema):
    refresh: str
    access: str
    status: str


class SimpleResponseSchema(Schema):
    is_success: bool


class SignUpByEmailSchema(Schema):
    email: str
    password: str
    nickname: str
