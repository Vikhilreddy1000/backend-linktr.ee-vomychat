from django.shortcuts import render
from rest_framework.views import APIView
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.response import Response
from .models import User, Referral
from .serializers import UserSerializer
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from datetime import timedelta
from django.utils import timezone
import random
import uuid
import json
# Create your views here.

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        referral_code = data.get('referral_code', None)
        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")
        if password != confirm_password:
            return Response({"message": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
            
        serializer = UserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        referrer = None
        if referral_code:
            try:
                referrer = User.objects.get(referral_code=referral_code)
            except User.DoesNotExist:
                return Response({"error": "Invalid referral code"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create(
            username=data['username'],
            email=data['email'],
            password=make_password(data['password']),
            password_hash=make_password(data['password']),
            referred_by=referrer
        )
        if referrer:
            Referral.objects.create(referrer=referrer, referred_user=user, status="successful")

        return Response({"message": "Signup Successfully"}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        user = authenticate(email=email, password=password)
        
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({'error': 'Invalid credentials'}, 
                      status=status.HTTP_401_UNAUTHORIZED)

class ForgetPasswordView(APIView):
    def post(self, request):
        email = request.POST.get("email")
        if not email:
            return Response({"message":  "Email field is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email) 
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            domain = get_current_site(request).domain
            reset_link = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            reset_url = f"http://{domain}{reset_link}"
            send_mail(
                'Password Reset Request',
                f'Hi {user.username},\n\nUse the link below to reset your password:\n{reset_url}',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            return Response({"message": "Password reset email sent"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"message": "No user found with this email.",}, status=status.HTTP_404_NOT_FOUND)
        
class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            new_password = request.data.get("new_password")
            confirm_password = request.data.get("confirm_password")

            if not new_password or not confirm_password:
                return Response({"message": "Both new_password and confirm_password are required."}, status=status.HTTP_400_BAD_REQUEST)

            if new_password != confirm_password:
                return Response({"message": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

            if len(new_password) < 8:
                return Response({"message": "Password must be at least 8 characters long."}, status=status.HTTP_400_BAD_REQUEST)

            user.password_hash = make_password(new_password)
            user.save()

            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
        return Response({"message": "Invalid or expired reset link."}, status=status.HTTP_400_BAD_REQUEST)

class ReferralLinkView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        domain = get_current_site(request).domain
        referral_link = f"http://{domain}/api/register?referral={user.referral_code}"
        return Response({"referral_link": referral_link}, status=status.HTTP_200_OK) 
    
class ReferralStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        print(user,"======")
        referrals = Referral.objects.filter(referrer=user, status='successful').count()
        return Response({"total_referrals": referrals}, status=status.HTTP_200_OK)