import os
from io import BytesIO
from uuid import uuid4
from dotenv import load_dotenv
from django.db import models
from django.core.files.storage import Storage, default_storage
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation

load_dotenv()

default_storage: Storage = default_storage

APP_NAME = os.getenv("DB_NAME")

if not APP_NAME:
    raise Exception("앱 이름이 정해지지 않았습니다")


class BaseModel(models.Model):
    class Meta:
        abstract = True

    created_at = models.DateTimeField(auto_now_add=True, null=False)
    updated_at = models.DateTimeField(auto_now=True, null=False)


class Image(BaseModel):
    user_id = models.PositiveIntegerField()

    content_type = models.ForeignKey(
        ContentType, related_name="images", on_delete=models.CASCADE
    )
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")

    url = models.TextField()
    path = models.CharField(max_length=1024)

    @classmethod
    def create_single_instance(
        cls, user_id: int, object: "CommonModel", image: BytesIO | InMemoryUploadedFile
    ):
        images = object.images.filter(object_id=object.pk)
        is_images = images.exists()
        if is_images:
            images.delete()
        return cls.create_image(user_id, object, image)

    def delete(self, *args, **kwargs) -> tuple[int, dict[str, int]]:

        default_storage.delete(self.path)
        return super(BaseModel, self).delete(*args, **kwargs)

    @classmethod
    def create_image(
        cls, user_id: int, object: models.Model, image: BytesIO | InMemoryUploadedFile
    ):
        model_name = object.__class__.__name__.lower()
        file_path = f"{APP_NAME}/{model_name}/{uuid4()}.jpeg"
        # with utils.Image.resize_image(image, "jpeg") as img:
        file_url = cls.save_image_to_storage(file_path, image)
        return Image.objects.create(
            user_id=user_id,
            content_object=object,
            url=file_url,
            path=file_path,
        )

    @classmethod
    def save_image_to_storage(
        cls, file_path: str, file: BytesIO | InMemoryUploadedFile
    ):
        default_storage.save(file_path, file)
        return default_storage.url(file_path)


class ImageMixin:
    images = GenericRelation(Image)


class CommonModel(ImageMixin, BaseModel):
    class Meta:
        abstract = True
