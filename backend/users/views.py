import time
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer, RegisterSerializer, UserPublicSerializer

class RegisterView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        ser = RegisterSerializer(data=request.data)
        if ser.is_valid():
            user = ser.save()
            return Response(
                {"message": "Usuario registrado", "user": UserPublicSerializer(user).data},
                status=status.HTTP_201_CREATED,
            )
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LoginView(APIView):
    authentication_classes = []     # público
    permission_classes = []         # público

    def post(self, request):
        ser = LoginSerializer(data=request.data, context={"request": request})
        if not ser.is_valid():
            # unificamos formato de error
            detail = ser.errors.get("detail", ["Datos inválidos"])[0]
            code = status.HTTP_401_UNAUTHORIZED if "credenciales" in detail.lower() else status.HTTP_403_FORBIDDEN
            return Response({"message": detail}, status=code)

        user = ser.validated_data["user"]
        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": UserPublicSerializer(user).data
        }, status=status.HTTP_200_OK)


class MeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({"user": UserPublicSerializer(request.user).data})
    
from .serializers import (
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    UserPublicSerializer,
)

token_generator = PasswordResetTokenGenerator()

class PasswordResetRequestView(APIView):
    authentication_classes = []
    permission_classes = []

    RATE_LIMIT_SECONDS = 3600  # 1 por hora

    def post(self, request):
        ser = PasswordResetRequestSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        user = ser.context["user"]
        # rate limit por email
        key = f"pwdreset:{user.email.lower()}"
        if cache.get(key):
            # 429 Too Many Requests
            return Response({"message": "Ya se solicitó un restablecimiento recientemente. Intenta más tarde."},
                            status=429)
        cache.set(key, True, self.RATE_LIMIT_SECONDS)

        uidb64 = urlsafe_base64_encode(smart_bytes(user.pk))
        token = token_generator.make_token(user)

        # arma enlace para el front si existe, si no, backend
        front_url = getattr(settings, "PASSWORD_RESET_CONFIRM_FRONTEND_URL", "")
        if front_url:
            link = f"{front_url}?uid={uidb64}&token={token}"
        else:
            link = request.build_absolute_uri(f"/api/auth/password/reset/confirm?uid={uidb64}&token={token}")

        subject = "Restablecer contraseña – Shift Scheduler"
        message = (
            f"Hola {user.first_name},\n\n"
            f"Solicitaste restablecer tu contraseña. Haz clic en el enlace (expira en 24 horas):\n\n{link}\n\n"
            "Si no fuiste tú, ignora este mensaje."
        )
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)

        # En desarrollo puedes (opcional) devolver los datos para facilitar test QA:
        if settings.DEBUG:
            return Response({"message": "Correo de restablecimiento enviado.", "uid": uidb64, "token": token},
                            status=200)
        return Response({"message": "Correo de restablecimiento enviado."}, status=200)


class PasswordResetConfirmView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        ser = PasswordResetConfirmSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        user = ser.context["user"]
        new_pw = ser.validated_data["new_password"]
        user.set_password(new_pw)
        user.save()
        return Response({"message": "Contraseña actualizada correctamente."}, status=200)
