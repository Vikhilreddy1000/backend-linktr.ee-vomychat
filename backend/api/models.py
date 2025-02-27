from django.db import models
from django.contrib.auth.models import AbstractUser
from datetime import datetime, date
from django.conf import settings
import uuid

# Create your models here.

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=128, unique=True)
    email = models.EmailField(blank=False, null=False, unique=True)
    password_hash = models.CharField(max_length=128)
    referral_code = models.CharField(max_length=10, unique=True, blank=True, null=True)
    referred_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='referrals_made')
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS =['username']

    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        if not self.referral_code:
            self.referral_code = str(uuid.uuid4())[:8]
        super().save(*args, **kwargs)
    
class Referral(models.Model):
    referrer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='referrals_given')
    referred_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='referred_by_referrer')
    status = models.CharField(max_length=10, choices=[('pending', 'Pending'), ('successful', 'Successful')], default='pending')
    date_referred = models.DateTimeField(auto_now_add=True)
