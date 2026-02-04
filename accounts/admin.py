from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, PasswordResetAuditLog


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom Admin interface for User model"""
    list_display = ['username', 'email', 'role', 'phone_number', 'is_active', 'date_joined']
    list_filter = ['role', 'is_active', 'is_staff', 'date_joined']
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Information', {
            'fields': ('role', 'phone_number')
        }),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Additional Information', {
            'fields': ('role', 'phone_number', 'email')
        }),
    )


@admin.register(PasswordResetAuditLog)
class PasswordResetAuditLogAdmin(admin.ModelAdmin):
    list_display = ['requested_at', 'user', 'result', 'email_attempted', 'email_success', 'sms_attempted', 'sms_success', 'ip_address']
    list_filter = ['result']
    readonly_fields = ['requested_at']
    search_fields = ['ip_address', 'user_agent']
