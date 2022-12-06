from rest_framework import serializers
from common_module.serializers import BaseSerializer, ImageSerializer, ImageInjector
from .models import User


class UserReadOnlySerializer(BaseSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "nickname", "role", "images")
        read_only_fields = ("role", "image")

    role = serializers.SerializerMethodField()
    images = ImageSerializer(many=True)

    def get_role(self, obj: User):
        return obj.get_roles()

    def update(self, instance, validated_data):
        return super().update(instance, validated_data)


class UserUpsertSerializer(BaseSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "nickname", "role", "image")
        read_only_fields = ("role", "image")

    role = serializers.SerializerMethodField()
    image = serializers.FileField(
        allow_empty_file=True, write_only=True, required=False
    )

    def get_role(self, obj: User):
        return obj.get_roles()

    @ImageInjector
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)
