from __future__ import absolute_import, unicode_literals

import base64

from datetime import timedelta, datetime
from typing import TypedDict

from celery import shared_task
from email.mime.text import MIMEText

from .models import User, ThirdPartyIntegration, Relationship

from accounts.email import get_email_login_html
from accounts.verify_storages import EmailVerifyStorage
from django.core.mail import EmailMessage, send_mail


class EmailLoginNecessaries(TypedDict):
    email: str
    callback: str
    scheme: str
    url: str


@shared_task
def send_verify_mail(id: int, data: EmailLoginNecessaries, code: str):
    user = User.objects.filter(id=id).first()
    if not user:
        return
    message = get_email_login_html(data=data, code=code, date=datetime.now())
    emailObject = EmailMessage("블로그 메일 인증 번호 입니다.", message, to=[data["email"]])
    emailObject.content_subtype = "html"
    result = emailObject.send()
