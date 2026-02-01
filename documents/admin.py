from django.contrib import admin
from .models import Document


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    """Admin interface for Document model"""
    list_display = ['student', 'document_type', 'title', 'uploaded_by', 'uploaded_at']
    list_filter = ['document_type', 'uploaded_at', 'uploaded_by']
    search_fields = ['student__username', 'student__email', 'title']
    readonly_fields = ['uploaded_at', 'updated_at']
    fieldsets = (
        ('Document Information', {
            'fields': ('student', 'document_type', 'title', 'file')
        }),
        ('Upload Information', {
            'fields': ('uploaded_by', 'uploaded_at', 'updated_at')
        }),
    )
