from django import forms
from rest_framework import serializers


class AuthenticateByTPForm(serializers.Serializer):
    type = serializers.CharField(required=True)
    token = serializers.CharField(required=True)


class AuthenticateByPasswordForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(required=True)


class AuthenticateByEmailForm(forms.Form):
    email = forms.EmailField(required=True)
    callback = forms.URLField(required=True)
    url = forms.CharField(required=True)
    scheme = forms.CharField(required=True)


class SignupByEmailForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(required=True)

    nickname = forms.CharField(required=True)


class ProfileImageUploadForm(forms.Form):
    image = forms.FileField(required=True)


class B64ProfileImageUploadForm(forms.Form):
    image = forms.CharField(required=True)


class EmailVerifyForm(forms.Form):
    code = forms.CharField(required=True)


class RefreshTokenForm(forms.Form):
    refresh = forms.CharField(required=True)
