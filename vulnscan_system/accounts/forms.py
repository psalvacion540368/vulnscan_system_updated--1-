from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ValidationError

from .models import User, Role


class RegistrationForm(UserCreationForm):
    """
    Public registration form.

    For security reasons, public users cannot select their own role.
    Every newly registered account starts as VIEWER.

    Only an administrator can later change the user's role.
    """

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "Email address",
                "autocomplete": "email",
            }
        ),
    )

    organization = forms.CharField(
        required=False,
        max_length=255,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Organization",
                "autocomplete": "organization",
            }
        ),
    )

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "organization",
            "password1",
            "password2",
        )

        widgets = {
            "username": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Username",
                    "autocomplete": "username",
                }
            ),
        }

    def clean_username(self):
        username = self.cleaned_data["username"].strip()

        if User.objects.filter(
            username__iexact=username
        ).exists():
            raise ValidationError(
                "An account with this username already exists."
            )

        return username

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()

        if User.objects.filter(
            email__iexact=email
        ).exists():
            raise ValidationError(
                "An account with this email already exists."
            )

        return email

    def save(self, commit=True):
        """
        Save the user securely.

        UserCreationForm handles password hashing.
        Public registration always creates VIEWER accounts.
        """

        user = super().save(commit=False)

        user.email = self.cleaned_data["email"]
        user.organization = self.cleaned_data.get(
            "organization",
            ""
        )

        # Security: never allow public registration
        # to create ADMIN or ANALYST accounts.
        user.role = Role.VIEWER

        if commit:
            user.save()

        return user


class LoginForm(AuthenticationForm):
    """
    Login form using Django's built-in authentication system.
    """

    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Username",
                "autocomplete": "username",
                "autofocus": True,
            }
        )
    )

    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Password",
                "autocomplete": "current-password",
            }
        )
    )


class AdminUserEditForm(forms.ModelForm):
    """
    Admin-only form for managing another user's:
    - Role
    - Active status
    - Organization
    """

    class Meta:
        model = User
        fields = (
            "role",
            "is_active",
            "organization",
        )

        widgets = {
            "role": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "is_active": forms.CheckboxInput(
                attrs={
                    "class": "form-check-input",
                }
            ),
            "organization": forms.TextInput(
                attrs={
                    "class": "form-control",
                }
            ),
        }
