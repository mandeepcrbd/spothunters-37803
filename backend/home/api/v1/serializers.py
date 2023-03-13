from django.contrib.auth import get_user_model, authenticate
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.http import HttpRequest
from django.utils.translation import ugettext_lazy as _
from allauth.account import app_settings as allauth_settings
from allauth.account.forms import ResetPasswordForm
from allauth.utils import email_address_exists, generate_unique_username
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from allauth.account.models import EmailAddress
from rest_framework import serializers
from rest_auth.serializers import PasswordResetSerializer
from users.models import OTP

User = get_user_model()


class SignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'name', 'email', 'password')
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {
                    'input_type': 'password'
                }
            },
            'email': {
                'required': True,
                'allow_blank': False,
            }
        }

    def _get_request(self):
        request = self.context.get('request')
        if request and not isinstance(request, HttpRequest) and hasattr(request, '_request'):
            request = request._request
        return request

    def validate_email(self, email):
        email = get_adapter().clean_email(email)
        if allauth_settings.UNIQUE_EMAIL:
            if email and email_address_exists(email):
                raise serializers.ValidationError(
                    _("A user is already registered with this e-mail address."))
        return email

    def create(self, validated_data):
        user = User(
            email=validated_data.get('email'),
            name=validated_data.get('name'),
            username=generate_unique_username([
                validated_data.get('name'),
                validated_data.get('email'),
                'user'
            ])
        )
        user.set_password(validated_data.get('password'))
        user.save()
        request = self._get_request()
        setup_user_email(request, user, [])


        # Welcome Email with OTP

        otp = OTP.objects.create(user=user)
        pin = otp.pin
        mail_subject = "[ParkAuthority] Please confirm your email address."
        message = render_to_string(
            "account/acc_activate_email.html", {"user": user, "pin": pin}
        )
        to_email = user.email
        email = EmailMessage(mail_subject, message, to=[to_email])
        email.send()

        return user

    def save(self, request=None):
        """rest_auth passes request so we must override to accept it"""
        return super().save()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name']


class PasswordSerializer(PasswordResetSerializer):
    """Custom serializer for rest_auth to solve reset password error"""
    password_reset_form_class = ResetPasswordForm


class LogInSerializer(serializers.Serializer):
    email = serializers.EmailField(label=_("Email"), write_only=True)
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if email and password:
            user = authenticate(request=self.context.get("request"),
                                email=email,
                                password=password
                                )
            email_address = EmailAddress.objects.filter(email=email)
            if not user:
                msg = _("Unable to log in with provided credentials.")
                raise serializers.ValidationError({"error": msg}, code="authorization")
            email_address = email_address.first()
            if not email_address.verified:
                msg = _("Email address not verified")
                raise serializers.ValidationError({"error": msg}, code="authorization")
        else:
            msg = _('Must include "email" and "password".')
            raise serializers.ValidationError({"error": msg}, code="authorization")

        attrs["user"] = user
        return attrs


class VerifyAccountSerializer(serializers.Serializer):
    pin = serializers.CharField(label=_("Pin"), max_length=4, default="9999")
    email = serializers.EmailField(label=_("Email"), write_only=True)
