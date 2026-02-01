"""
URL patterns for Documents app
"""
from django.urls import path
from . import views

app_name = 'documents'

urlpatterns = [
    path('upload/', views.document_upload, name='upload'),
    path('admin/upload/<int:student_id>/', views.admin_document_upload, name='admin_upload'),
    path('download/<int:document_id>/', views.document_download, name='download'),
    path('delete/<int:document_id>/', views.document_delete, name='delete'),
]
