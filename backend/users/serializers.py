from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_str, smart_bytes
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import serializers
from .models import User
from .validators import validate_password_strength

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ("id","first_name","last_name","telefono","email","password","password_confirm","role")
        read_only_fields = ("id",)

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("El correo ya está registrado.")
        return value

    def validate(self, attrs):
        pw = attrs.get("password")
        pw2 = attrs.pop("password_confirm", None)
        if pw != pw2:
            raise serializers.ValidationError({"password_confirm": "Las contraseñas no coinciden."})
        validate_password_strength(pw)
        return attrs

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])
        return User.objects.create(**validated_data)

class UserPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id","first_name","last_name","telefono","email","role","status")

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        user = authenticate(request=self.context.get("request"), email=email, password=password)
        if not user:
            # 401 credenciales inválidas
            raise serializers.ValidationError({"detail": "Credenciales inválidas."})

        # Reglas por estado del usuario
        if not user.is_active or user.status in ("BLOCKED", "INACTIVE"):
            # 403 estado no permitido
            raise serializers.ValidationError({"detail": "Usuario no autorizado. Verifica tu estado."})

        attrs["user"] = user
        return attrs

User = get_user_model()
token_generator = PasswordResetTokenGenerator()

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email__iexact=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Correo no registrado.")
        self.context["user"] = user
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    new_password_confirm = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError({"new_password_confirm": "Las contraseñas no coinciden."})
        # validación de política de contraseña
        validate_password(attrs["new_password"])
        return attrs

    def validate_uid(self, value):
        try:
            uid = force_str(urlsafe_base64_decode(value))
            user = User.objects.get(pk=uid)
        except Exception:
            raise serializers.ValidationError("UID inválido.")
        self.context["user"] = user
        return value

    def validate_token(self, value):
        # el user se coloca en validate_uid
        user = self.context.get("user")
        if not user or not token_generator.check_token(user, value):
            raise serializers.ValidationError("Token inválido o expirado.")
        return value