from typing import TypedDict
import functools
from rest_framework import serializers

from .utils import MockRequest
from .models import Image


class SerializerContext(TypedDict):
    request: MockRequest


class BaseSerializer(serializers.ModelSerializer):
    context: SerializerContext


class ImageSerializer(BaseSerializer):
    class Meta:
        model = Image
        fields = ("url", "path")


def ImageInjector(func):
    @functools.wraps(func)
    def wrapper(self, *args):
        validated_data = args[-1]
        image = validated_data.pop("image", None)
        user_id = self.context["request"].user.get("id")
        if func.__name__ == "create":
            instance = func(self, validated_data)
        else:
            obj = args[0]
            instance = func(self, obj, validated_data)

        if image:
            Image.create_single_instance(user_id, instance, image)
        return instance

    return wrapper
