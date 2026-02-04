"""
Custom User Model for MBBS Visa Management System
Supports Student and Admin roles
"""
from django.contrib.auth.models import AbstractUser, UserManager
from django.db import models
from django.utils import timezone


class CustomUserManager(UserManager):
    def create_superuser(self, username, email=None, password=None, **extra_fields):
        """
        Ensure superusers are always treated as Admins in this app.

        Django's default superuser creation doesn't know about our `role` field,
        so without this override a superuser would default to role=STUDENT.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'ADMIN')

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return super().create_superuser(username, email=email, password=password, **extra_fields)


class User(AbstractUser):
    """
    Custom User Model extending Django's AbstractUser
    Roles: STUDENT, ADMIN
    """
    ROLE_CHOICES = [
        ('STUDENT', 'Student'),
        ('ADMIN', 'Admin'),
    ]
    
    role = models.CharField(
        max_length=10,
        choices=ROLE_CHOICES,
        default='STUDENT',
        help_text='User role: Student or Admin'
    )
    phone_number = models.CharField(
        max_length=15,
        blank=True,
        null=True,
        help_text='Contact phone number'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # Temporary password (one-time, for forgot-password flow). When set, login forces password change.
    temp_password_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='If set, user has a temporary password valid until this time (one-time use).'
    )

    objects = CustomUserManager()
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
    
    def is_student(self):
        """Check if user is a student"""
        return self.role == 'STUDENT'
    
    def is_admin(self):
        """Check if user is an admin (role=ADMIN or staff/superuser for Django admin access)."""
        return self.role == 'ADMIN' or self.is_staff or self.is_superuser


class Notification(models.Model):
    """
    Simple in-app notification shown to a user on their dashboard.
    Used to notify students when an admin deletes a document and requests re-upload.
    """
    user = models.ForeignKey(
        'accounts.User',
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    message = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f"Notification(to={self.user.username}, read={self.is_read})"


class PasswordResetAuditLog(models.Model):
    """
    Audit log for forgot-password requests. Never store plaintext passwords.
    """
    RESULT_SENT = 'sent'
    RESULT_RATE_LIMIT_USER = 'rate_limit_user'
    RESULT_RATE_LIMIT_IP = 'rate_limit_ip'
    RESULT_NO_MATCH = 'no_match'
    RESULT_CHOICES = [
        (RESULT_SENT, 'Sent'),
        (RESULT_RATE_LIMIT_USER, 'Rate limit (per user)'),
        (RESULT_RATE_LIMIT_IP, 'Rate limit (per IP)'),
        (RESULT_NO_MATCH, 'No matching student'),
    ]

    user = models.ForeignKey(
        'accounts.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='password_reset_audit_logs',
        help_text='Null if no matching student (non-enumeration).'
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    email_attempted = models.BooleanField(default=False)
    email_success = models.BooleanField(default=False)
    sms_attempted = models.BooleanField(default=False)
    sms_success = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    result = models.CharField(max_length=32, choices=RESULT_CHOICES)

    class Meta:
        ordering = ['-requested_at']
        verbose_name = 'Password reset audit log'
        verbose_name_plural = 'Password reset audit logs'

    def __str__(self):
        return f"Reset audit {self.requested_at} result={self.result}"
