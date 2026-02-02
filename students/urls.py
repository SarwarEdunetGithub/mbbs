"""
URL patterns for Students app
"""
from django.urls import path
from . import views

app_name = 'students'

urlpatterns = [
    path('dashboard/', views.student_dashboard, name='dashboard'),
    path('profile/edit/', views.student_profile_edit, name='profile_edit'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/student/<int:student_id>/', views.student_detail, name='student_detail'),
    path('admin/student/<int:student_id>/edit/', views.admin_student_edit, name='admin_student_edit'),
    path('admin/student/<int:student_id>/edit/confirm/', views.admin_student_edit_confirm, name='admin_student_edit_confirm'),
    path('admin/student/<int:student_id>/delete/', views.admin_student_delete, name='admin_student_delete'),
]
