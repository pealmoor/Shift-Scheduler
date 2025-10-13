from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import RegisterView, LoginView, MeView, PasswordResetRequestView, PasswordResetConfirmView

urlpatterns = [
    path("register", RegisterView.as_view(), name="auth-register"),
    path("login", LoginView.as_view(), name="auth-login"),
    path("token/refresh", TokenRefreshView.as_view(), name="token-refresh"),
    path("me", MeView.as_view(), name="auth-me"),
    path("password/reset", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password/reset/confirm", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
]
