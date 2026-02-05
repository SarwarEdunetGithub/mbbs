"""
URL patterns for Accounts app
"""
from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('', views.landing_page, name='landing'),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('register/send-otp/', views.send_otp_view, name='send_otp'),
    path('register/verify-otp/', views.verify_otp_view, name='verify_otp'),
]
