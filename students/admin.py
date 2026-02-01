from django.contrib import admin
from django.utils.html import format_html
from .models import StudentProfile


@admin.register(StudentProfile)
class StudentProfileAdmin(admin.ModelAdmin):
    """Admin interface for Student Profile"""
    list_display = ['photo_thumbnail', 'user', 'passport_number', 'visa_status', 'created_at']
    list_filter = ['visa_status', 'created_at']
    search_fields = ['user__username', 'user__email', 'passport_number', 'user__first_name', 'user__last_name']
    readonly_fields = ['created_at', 'updated_at', 'photo_preview']
    fieldsets = (
        ('User Information', {
            'fields': ('user', 'photo', 'photo_preview')
        }),
        ('Visa Information', {
            'fields': ('passport_number', 'address', 'visa_status')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def photo_thumbnail(self, obj):
        """Display small photo thumbnail in list view"""
        if obj.photo:
            return format_html(
                '<img src="{}" style="width: 40px; height: 40px; border-radius: 50%; object-fit: cover;" />',
                obj.photo.url
            )
        return format_html(
            '<div style="width: 40px; height: 40px; border-radius: 50%; background: #e9ecef; display: flex; align-items: center; justify-content: center;">'
            '<span style="color: #6c757d;">N/A</span></div>'
        )
    photo_thumbnail.short_description = 'Photo'
    
    def photo_preview(self, obj):
        """Display larger photo preview in detail view"""
        if obj.photo:
            return format_html(
                '<img src="{}" style="max-width: 200px; max-height: 200px; border-radius: 8px;" />',
                obj.photo.url
            )
        return "No photo uploaded"
    photo_preview.short_description = 'Photo Preview'
