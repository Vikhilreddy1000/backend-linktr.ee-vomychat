from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Referral

# Register your models here.

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ("email",)
    list_filter = ("email",)
    fieldsets = (
        (None, {"fields": ("username", "email", "password")}),
        ("Additional fields", {"fields": ("password_hash", "referral_code", "referred_by")}),

    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "email", "password", "is_active"
            )}
        ),
    )
    search_fields = ("email",)
    ordering = ("email",)

admin.site.register(User,CustomUserAdmin)

class ReferralAdmin(admin.ModelAdmin):
    fields = [
        'referrer',
        'referred_user',
        'status'
    ]
    list_display = [
       'referrer',
       'referred_user',
       'status',
       'date_referred'
    ]
admin.site.register(Referral,ReferralAdmin)
