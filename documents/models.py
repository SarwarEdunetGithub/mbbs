"""
Document Model for file uploads
"""
from django.db import models
from django.conf import settings
import os


def document_upload_path(instance, filename):
    """
    Generate upload path for documents
    Format: documents/{student_username}/{document_type}/{filename}
    """
    return f'documents/{instance.student.username}/{instance.document_type}/{filename}'


class Document(models.Model):
    """
    Document Model
    Stores uploaded documents for students
    """
    DOCUMENT_TYPE_CHOICES = [
        ('10TH_MARKSHEET', '10th Marksheet'),
        ('12TH_MARKSHEET', '12th Marksheet'),
        ('AADHAAR', 'Aadhaar Card'),
        ('PAN', 'PAN Card'),
        ('ADDITIONAL', 'Additional Document'),
    ]
    
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='documents'
    )
    document_type = models.CharField(
        max_length=20,
        choices=DOCUMENT_TYPE_CHOICES,
        help_text='Type of document'
    )
    file = models.FileField(
        upload_to=document_upload_path,
        help_text='Upload document file'
    )
    title = models.CharField(
        max_length=255,
        blank=True,
        help_text='Optional title for the document'
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='uploaded_documents',
        help_text='User who uploaded this document'
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Document'
        verbose_name_plural = 'Documents'
        ordering = ['-uploaded_at']
        unique_together = [['student', 'document_type', 'title']]
    
    def __str__(self):
        return f"{self.student.username} - {self.get_document_type_display()}"
    
    def filename(self):
        """Get filename from file path"""
        if not self.file or not self.file.name:
            return ''
        return os.path.basename(self.file.name)
    
    def file_size(self):
        """Get file size in KB"""
        try:
            size = self.file.size
            return round(size / 1024, 2)  # Convert to KB
        except:
            return 0
    
    def is_uploaded_by_admin(self):
        """Check if document was uploaded by admin"""
        return self.uploaded_by and self.uploaded_by.is_admin()
