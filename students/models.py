"""
Student Profile Model
Stores additional information for students
"""
from django.db import models
from django.conf import settings
from django.core.validators import RegexValidator


def student_photo_path(instance, filename):
    """Generate upload path for student photos"""
    return f'student_photos/{instance.user.username}/{filename}'


class StudentProfile(models.Model):
    """
    Student Profile Model
    Extended information for visa processing
    """
    STATUS_CHOICES = [
        ('REGISTERED', 'Registered'),
        ('DOCUMENTS_SUBMITTED', 'Documents Submitted'),
        ('UNDER_REVIEW', 'Under Review'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    ]
    
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='student_profile'
    )
    photo = models.ImageField(
        upload_to=student_photo_path,
        blank=True,
        null=True,
        help_text='Student passport-size photo'
    )
    passport_number = models.CharField(
        max_length=20,
        unique=True,
        blank=True,
        null=True,
        help_text='Passport number (unique identifier)'
    )
    address = models.TextField(
        blank=True,
        null=True,
        help_text='Complete residential address'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    visa_status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='REGISTERED',
        help_text='Current visa processing status'
    )
    
    class Meta:
        verbose_name = 'Student Profile'
        verbose_name_plural = 'Student Profiles'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username} - {self.passport_number}"
    
    def get_status_display_class(self):
        """Return Bootstrap class for status badge"""
        status_classes = {
            'REGISTERED': 'secondary',
            'DOCUMENTS_SUBMITTED': 'info',
            'UNDER_REVIEW': 'warning',
            'APPROVED': 'success',
            'REJECTED': 'danger',
        }
        return status_classes.get(self.visa_status, 'secondary')
