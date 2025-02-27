from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from .models import User

# Create your tests here.

class RegistrationTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.valid_payload = {
            "username": "vikhil123",
            "email": "vikhil@yopmail.com",
            "password": "Vikhil@123"
        }

    def test_valid_registration(self):
        response = self.client.post('/api/register/', self.valid_payload)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email="vikhil@yopmail.com").exists())

    def test_duplicate_email(self):
        User.objects.create_user(username="vikhil123", email="vikhil@yopmail.com", password="Vikhil@123")
        response = self.client.post('/api/register/', self.valid_payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Email already in use", response.data["email"])

    def test_invalid_email(self):
        payload = {**self.valid_payload, "email": "invalid-email"}
        response = self.client.post('/api/register/', payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Enter a valid email address", response.data["email"])

    def test_weak_password(self):
        payload = {**self.valid_payload, "password": "weak"}
        response = self.client.post('/api/register/', payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Password must be at least 8 characters long", response.data["password"])


class LoginTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="securepassword123"
        )
        self.valid_payload = {"email": "test@example.com", "password": "securepassword123"}
        self.invalid_payload = {"email": "test@example.com", "password": "wrongpassword"}

    def test_successful_login(self):
        response = self.client.post('/api/login/', self.valid_payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_invalid_credentials(self):
        response = self.client.post('/api/login/', self.invalid_payload)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("Invalid credentials", response.data["error"])

    def test_inactive_user(self):
        self.user.is_active = False
        self.user.save()
        response = self.client.post('/api/login/', self.valid_payload)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("User account is disabled", response.data["error"])


from .models import Referral

class ReferralSystemTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.referrer = User.objects.create_user(
            username="referrer",
            email="referrer@example.com",
            password="password123"
        )
        self.valid_referral_payload = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "securepassword123",
            "referral_code": self.referrer.referral_code
        }
        self.invalid_referral_payload = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "securepassword123",
            "referral_code": "INVALID_CODE"
        }

    def test_register_with_valid_referral(self):
        response = self.client.post('/api/register/', self.valid_referral_payload)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Referral.objects.filter(referrer=self.referrer).exists())

    def test_register_with_invalid_referral(self):
        response = self.client.post('/api/register/', self.invalid_referral_payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid referral code", response.data["error"])

    def test_self_referral(self):
        payload = {
            "username": "selfreferrer",
            "email": "selfreferrer@example.com",
            "password": "securepassword123",
            "referral_code": self.referrer.referral_code
        }
        self.client.force_authenticate(user=self.referrer)
        response = self.client.post('/api/register/', payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("You cannot refer yourself", response.data["error"])

    def test_referral_count(self):
        self.client.post('/api/register/', self.valid_referral_payload)
        self.client.logout()
        self.client.force_authenticate(user=self.referrer)
        response = self.client.get('/api/referral-stats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_referrals"], 1)