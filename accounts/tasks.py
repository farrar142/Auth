from __future__ import absolute_import, unicode_literals

import base64

from datetime import timedelta, datetime
from typing import TypedDict

from celery import shared_task
from email.mime.text import MIMEText

from .models import User, ThirdPartyIntegration, Relationship

from accounts.email import get_email_login_html
from accounts.verify_storages import EmailVerifyStorage
from accounts.utils import get_credentials


@shared_task
def send_verify_mail(id: int, data):
    storage = EmailVerifyStorage()
    user = User.objects.filter(id=id).first()
    if not user:
        return
    code = storage.set(user)
    storage.set_email_term(user)
    service = get_credentials()
    message = MIMEText(
        get_email_login_html(data=data, code=code, date=datetime.now()),
        "html",
    )
    message["to"] = user.email
    message["from"] = "gksdjf1690@gmail.com"
    message["subject"] = "블로그 로그인 인증 메일입니다."
    raw_message_no_attachment = base64.urlsafe_b64encode(message.as_bytes())
    raw_message_no_attachment = raw_message_no_attachment.decode()
    body = {"raw": raw_message_no_attachment}

    try:
        service.users().messages().send(userId="me", body=body).execute()
        return True
    except Exception as e:
        print(e)
        return False
