from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
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