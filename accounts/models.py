from typing import Optional, Literal
from datetime import datetime, timedelta
from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.fields import GenericRelation

from django.db import models

from common_module.models import CommonModel, Image

# Create your models here.


class User(AbstractUser):
    # TIMEZONES = tuple(zip(pytz.all_timezones, pytz.all_timezones))

    nickname = models.CharField(max_length=32, blank=False, null=False)

    profile_image_url = models.TextField(blank=False, null=True)
    profile_image_path = models.CharField(max_length=1024, blank=False, null=True)

    last_accessed_at = models.DateTimeField(auto_now_add=True, null=False)

    terms_agree_at = models.DateTimeField(null=True)

    is_verified = models.BooleanField(default=False)
    verify_token = models.CharField(max_length=6, null=True, blank=True)

    users_following: models.Manager["User"]
    users_followers: models.Manager["User"]
    users_blocking: models.Manager["Block"]
    tp_integrations: models.Manager["ThirdPartyIntegration"]
    images = GenericRelation(Image)

    def get_roles(self):
        roles: list[str] = []
        if self.is_staff:
            roles.append("staff")
        return roles

    def has_blocked(self, user: "User"):
        return self.users_blocking.filter(user_to=user).exists()

    def set_verify_token(self, token: str):
        self.verify_token = token

    def get_tp_integration(self, type: str):
        """서드 파티 연동 정보를 반환합니다."""
        try:
            return self.tp_integrations.get(type=type)
        except ThirdPartyIntegration.DoesNotExist:
            return None

    def has_tp_integration(self, type: str):
        """서드 파티 연동 정보가 있는지 확인합니다."""
        return self.get_tp_integration(type) is not None

    def get_credentials(self):
        return {"username": self.username, "password": self.password}


class ThirdPartyIntegration(CommonModel):
    class IntegrationType(models.TextChoices):
        APPLE = ("apple", "Apple")
        FACEBOOK = ("facebook", "Facebook")
        GOOGLE = ("google", "Google")
        KAKAO = ("kakao", "KakaoTalk")

    class Meta:
        unique_together = ("user", "type")

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="tp_integrations", null=False
    )
    type = models.CharField(null=False, choices=IntegrationType.choices, max_length=16)
    # 서드 파티의 사용자 식별자 (일반적으로는 user_id, Apple의 경우 jwt_token.sub)
    identifier = models.CharField(null=False, max_length=2048)
    token = models.TextField(null=True, blank=True)


class Relationship(CommonModel):
    class Meta:
        unique_together = ("user_from", "user_to")

    user_from = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="users_following", null=False
    )
    user_to = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="users_followers", null=False
    )

    @staticmethod
    def is_following(user_from: User, user_to: User) -> bool:
        return Relationship.objects.filter(
            user_from=user_from, user_to=user_to
        ).exists()

    @staticmethod
    def follow(user_from: User, user_to: User) -> Optional["Relationship"]:
        if user_to.has_blocked(user_from) or user_from.has_blocked(user_to):
            raise Exception()  # FIXME

        relationship = Relationship()
        relationship.user_from = user_from
        relationship.user_to = user_to

        relationship.save()

        return relationship


class Block(CommonModel):
    class Meta:
        unique_together = ("user_from", "user_to")

    user_from = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="users_blocking", null=False
    )
    user_to = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="users_blocked_by", null=False
    )
