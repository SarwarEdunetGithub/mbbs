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
