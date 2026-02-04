"""
Auth namespace URLs: /auth/forgot-password/, /auth/login/, /auth/force-change-password/
"""
from django.urls import path
from . import views

app_name = 'auth'

urlpatterns = [
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('login/', views.login_view, name='login'),
    path('force-change-password/', views.force_change_password_view, name='force_change_password'),
]
