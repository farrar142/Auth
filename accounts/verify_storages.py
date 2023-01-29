from typing import Literal, Optional, Union
from uuid import uuid4
from django.core.cache import cache, BaseCache
from .models import User

MINUTE = 60
HOUR = MINUTE * 24


class EmailVerifyStorage:
    cache: BaseCache = cache

    def email_terms_key(self, user):
        return f"email_terms:{user.pk}"

    def get_email_term(self, user: User, duration=3 * MINUTE):
        email_key = self.email_terms_key(user)
        if self.cache.get(email_key, False):
            return True
        return False

    def drop_email_term(self, user: User):
        email_key = self.email_terms_key(user)
        self.cache.delete(email_key)

    def set_email_term(self, user: User, duration=3 * MINUTE):
        email_key = self.email_terms_key(user)
        if self.cache.get(email_key, False):
            return False
        self.cache.set(self.email_terms_key(user), True, duration)
        return True

    def set(self, user: User):
        key = str(uuid4())
        self.cache.set(key, user.pk, timeout=HOUR)
        return key

    def get(self, key: str):
        user_id: Union[int, Literal[False]] = self.cache.get(key, None)
        if not user_id:
            return False
        user = User.objects.filter(id=user_id).first()
        if not user:
            return False
        self.cache.delete(key)
        return user
