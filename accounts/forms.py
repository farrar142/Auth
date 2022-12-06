from django import forms


class AuthenticateByEmailForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(required=True)


class AuthenticateByTPForm(forms.Form):
    type = forms.CharField(required=True)
    token = forms.CharField(required=True)


class SignupByEmailForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(required=True)

    nickname = forms.CharField(required=True)


class ProfileImageUploadForm(forms.Form):
    image = forms.FileField(required=True)


class B64ProfileImageUploadForm(forms.Form):
    image = forms.CharField(required=True)
