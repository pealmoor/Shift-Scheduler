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
