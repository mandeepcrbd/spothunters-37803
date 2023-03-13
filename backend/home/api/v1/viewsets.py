from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework import status
from rest_framework.viewsets import ModelViewSet, ViewSet
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from allauth.account.models import EmailAddress

from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from users.models import OTP

from home.api.v1.serializers import SignupSerializer, UserSerializer, LogInSerializer, VerifyAccountSerializer


class SignupViewSet(ModelViewSet):
    serializer_class = SignupSerializer
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Verification e-mail sent."}, status=status.HTTP_202_ACCEPTED)


class LoginViewSet(ModelViewSet):
    """Based on rest_framework.authtoken.views.ObtainAuthToken"""

    serializer_class = LogInSerializer
    http_method_names = ['post']

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        user = serializer.validated_data["user"]
        token, created = Token.objects.get_or_create(user=user)
        user_serializer = UserSerializer(user)
        return Response({"token": token.key, "user": user_serializer.data})


class VerifyAccountViewSet(ModelViewSet):
    serializer_class = VerifyAccountSerializer
    permission_classes = [AllowAny, ]
    http_method_names = ["post"]

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email_address = get_object_or_404(EmailAddress, email=request.data.get("email"))

        otp = get_object_or_404(OTP, user=email_address.user)
        is_valid = otp.validate_otp(pin=request.data.get("pin"))
        if is_valid:
            email_address.verified = True
            email_address.save()
            return Response({"message": "Email address verified"}, status=status.HTTP_202_ACCEPTED)
        return Response({"message": "Invalid pin"}, status=status.HTTP_400_BAD_REQUEST)