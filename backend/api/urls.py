from django.urls import path
from .views import *

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/forgot-password/', ForgetPasswordView.as_view(), name='forgot_password'),
    path('api/reset-password/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('api/referral-stats/', ReferralStatsView.as_view(), name='referral_stats'),
    path('api/referral-link/', ReferralLinkView.as_view(), name='referral_link')
]
