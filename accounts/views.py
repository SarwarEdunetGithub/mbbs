"""
Authentication Views: Login, Register, Logout, Landing Page, Change Password, Forgot Password
"""
import logging
import secrets
import string
import time
from datetime import timedelta
from django.shortcuts import render, redirect
from django.db.models import Q
from django.http import JsonResponse
import json
from django.contrib.auth import login, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache
from .forms import (
    StudentRegistrationForm,
    LoginForm,
    ChangePasswordForm,
    ForgotPasswordForm,
    ForceChangePasswordForm,
)
from .models import User, PasswordResetAuditLog
from .notifications import send_email, send_sms

logger = logging.getLogger(__name__)

# Rate limit for change-password failures (no extra frameworks)
PASSWORD_CHANGE_RATE_LIMIT_COUNT = 5
PASSWORD_CHANGE_RATE_LIMIT_SECONDS = 900  # 15 minutes

# Uniform response delay for forgot-password (reduce enumeration risk), seconds
FORGOT_PASSWORD_RESPONSE_DELAY = 0.5


def _generate_otp(length=6):
    """Generate a 6-digit OTP."""
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def _generate_temporary_password(length=8):
    """Strong random password: mixed classes. Never log this."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Ensure at least one of each class
    pwd = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return ''.join(pwd)


def _get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')[:45]


def _get_user_agent(request):
    return (request.META.get('HTTP_USER_AGENT') or '')[:500]


def landing_page(request):
    """
    Landing Page - Redirect to dashboard if logged in
    """
    if request.user.is_authenticated:
        if request.user.is_admin():
            return redirect('students:admin_dashboard')
        return redirect('students:dashboard')
    return render(request, 'accounts/landing.html')


def send_otp_view(request):
    """
    Send OTP to the provided email address.
    Expects JSON payload: {"email": "user@example.com"}
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=405)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON.'}, status=400)

    if not email:
        return JsonResponse({'success': False, 'message': 'Email is required.'}, status=400)

    # Check if user already exists
    if User.objects.filter(email=email).exists():
        return JsonResponse({'success': False, 'message': 'An account with this email already exists.'}, status=400)

    otp = _generate_otp()
    
    # Store OTP in session with expiration (e.g., 5 minutes)
    request.session['registration_otp'] = otp
    request.session['registration_email'] = email
    request.session['otp_expires_at'] = (timezone.now() + timedelta(minutes=5)).isoformat()
    request.session['email_verified'] = False  # Reset verification status
    
    # Send email
    subject = "Verify your email - Aspire Abroad"
    body = f"Your verification code is: {otp}\n\nThis code will expire in 5 minutes."
    
    if send_email(email, subject, body):
        return JsonResponse({'success': True, 'message': 'OTP sent successfully.'})
    else:
        return JsonResponse({'success': False, 'message': 'Failed to send OTP. Please try again.'}, status=500)


def verify_otp_view(request):
    """
    Verify the OTP provided by the user.
    Expects JSON payload: {"otp": "123456", "email": "user@example.com"}
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=405)

    try:
        data = json.loads(request.body)
        user_otp = data.get('otp', '').strip()
        email = data.get('email', '').strip()
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON.'}, status=400)

    session_otp = request.session.get('registration_otp')
    session_email = request.session.get('registration_email')
    expires_at_str = request.session.get('otp_expires_at')

    if not session_otp or not session_email or not expires_at_str:
        return JsonResponse({'success': False, 'message': 'No OTP request found. Please request a new code.'}, status=400)

    if email != session_email:
        return JsonResponse({'success': False, 'message': 'Email does not match the OTP request.'}, status=400)

    # Check expiration
    expires_at = timezone.datetime.fromisoformat(expires_at_str)
    if timezone.now() > expires_at:
        return JsonResponse({'success': False, 'message': 'OTP has expired. Please request a new one.'}, status=400)

    if user_otp == session_otp:
        request.session['email_verified'] = True
        return JsonResponse({'success': True, 'message': 'Email verified successfully.'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid OTP.'}, status=400)


def register_view(request):
    """
    Student Registration View
    Only students can register themselves
    """
    if request.user.is_authenticated:
        if request.user.is_student():
            return redirect('students:dashboard')
        elif request.user.is_admin():
            return redirect('students:admin_dashboard')
    
    if request.method == 'POST':
        form = StudentRegistrationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            
            # Verify email verification status
            if not request.session.get('email_verified'):
                messages.error(request, 'Please verify your email address.')
                return render(request, 'accounts/register.html', {'form': form})
            
            if request.session.get('registration_email') != email:
                messages.error(request, 'The verified email does not match the form email.')
                return render(request, 'accounts/register.html', {'form': form})

            user = form.save(commit=False)
            user.role = 'STUDENT'
            user.set_password(form.cleaned_data['password'])
            user.save()
            
            # Clean up session
            request.session.pop('email_verified', None)
            request.session.pop('registration_email', None)
            request.session.pop('registration_otp', None)
            request.session.pop('otp_expires_at', None)
            
            messages.success(
                request,
                'Registration successful! Please login with your credentials.'
            )
            return redirect('accounts:login')
    else:
        form = StudentRegistrationForm()
    
    return render(request, 'accounts/register.html', {'form': form})


def login_view(request):
    """
    Login View for both Students and Admins.
    """
    if request.user.is_authenticated:
        if getattr(request.session, 'get') and request.session.get('must_change_password'):
            return redirect('auth:force_change_password')
        if request.user.is_student():
            return redirect('students:dashboard')
        elif request.user.is_admin():
            return redirect('students:admin_dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            remember_me = form.cleaned_data.get('remember_me', True)
            user = authenticate(request, username=username, password=password)

            if user is not None:
                if user.is_active:
                    now = timezone.now()
                    # Expired temp password: reject login
                    if user.temp_password_expires_at and user.temp_password_expires_at <= now:
                        messages.error(
                            request,
                            'Your temporary password has expired. Please use "Forgot password" again to receive a new one.',
                        )
                        return render(request, 'accounts/login.html', {'form': form})

                    login(request, user)
                    if not remember_me:
                        request.session.set_expiry(0)

                    # One-time temp password: require immediate change and invalidate temp
                    if user.temp_password_expires_at and user.temp_password_expires_at > now:
                        request.session['must_change_password'] = True
                        # Invalidate temp password so it cannot be used again
                        user.set_password(secrets.token_urlsafe(32))
                        user.temp_password_expires_at = None
                        user.save(update_fields=['password', 'temp_password_expires_at'])
                        
                        # Update session auth hash to prevent logout
                        update_session_auth_hash(request, user)

                        messages.info(request, 'Please set a new password to continue.')
                        return redirect('auth:force_change_password')

                    messages.success(request, f'Welcome, {user.get_full_name() or user.username}!')
                    if user.is_admin():
                        return redirect('students:admin_dashboard')
                    return redirect('students:dashboard')
                messages.error(request, 'Your account has been disabled.')
            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})


def forgot_password_view(request):
    """
    Forgot password: Input username OR email.
    If exists: send email with username and 8-digit temp password.
    If not exists: Show "Student does not exist".
    """
    if request.user.is_authenticated:
        return redirect('students:dashboard')

    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            username_or_email = form.cleaned_data.get('username_or_email')
            
            # Find user by email or username, restricted to students
            user = User.objects.filter(
                (Q(email__iexact=username_or_email) | Q(username__iexact=username_or_email)) & 
                Q(role='STUDENT')
            ).first()

            if user:
                # Generate 8-digit temp password
                temp_password = _generate_temporary_password(length=8)
                user.set_password(temp_password)
                
                # Set expiration (15 mins)
                valid_minutes = getattr(settings, 'PASSWORD_RESET_TEMP_VALID_MINUTES', 15)
                expires_at = timezone.now() + timedelta(minutes=valid_minutes)
                user.temp_password_expires_at = expires_at
                
                # Save changes
                user.save(update_fields=['password', 'temp_password_expires_at'])

                # Send email
                if getattr(settings, 'SEND_EMAIL_ENABLED', True) and user.email:
                    subject = 'Password Reset - Aspire Abroad'
                    body = (
                        f"Hello {user.username},\n\n"
                        f"We received a request to reset your password.\n"
                        f"Your temporary password is: {temp_password}\n\n"
                        f"This password is valid for {valid_minutes} minutes.\n"
                        f"Please login using this temporary password and set a new password immediately."
                    )
                    send_email(user.email, subject, body)
                    
                    messages.success(
                        request,
                        'A temporary password has been sent to your registered email address.',
                    )
                else:
                    # Fallback if email disabled or missing (though student should have email)
                    messages.warning(request, 'Unable to send email. Please contact support.')
            else:
                messages.error(request, 'Student does not exist.')
            
            return redirect('accounts:forgot_password')
    else:
        form = ForgotPasswordForm()

    return render(request, 'accounts/forgot_password.html', {'form': form})


@login_required(login_url='auth:login')
def force_change_password_view(request):
    """
    Mandatory password change after logging in with a temporary password.
    Requires session flag must_change_password; clears it on success.
    """
    if not request.session.get('must_change_password'):
        return redirect('students:dashboard')

    if request.method == 'POST':
        form = ForceChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            request.user.set_password(form.cleaned_data['new_password'])
            request.user.save(update_fields=['password'])
            if request.user.temp_password_expires_at:
                request.user.temp_password_expires_at = None
                request.user.save(update_fields=['temp_password_expires_at'])
            del request.session['must_change_password']
            update_session_auth_hash(request, request.user)
            messages.success(request, 'Your password has been set. You can now use the dashboard.')
            return redirect('students:dashboard')
    else:
        form = ForceChangePasswordForm(request.user)

    return render(request, 'accounts/force_change_password.html', {'form': form})


@login_required(login_url='accounts:login')
def change_password_view(request):
    """
    Secure change-password view for authenticated users.
    - CSRF enforced by Django middleware.
    - Verifies current password; enforces AUTH_PASSWORD_VALIDATORS on new password.
    - Re-authenticates session (update_session_auth_hash), rotates session key.
    - Rate-limits failed attempts; logs success.
    - Optional: invalidate other sessions (see PASSWORD_CHANGE_INVALIDATE_OTHER_SESSIONS in notes).
    """
    user = request.user
    cache_key = f'pwd_change_fail:{user.pk}'
    rate_data = cache.get(cache_key) or {'count': 0}

    if request.method == 'POST':
        if rate_data['count'] >= PASSWORD_CHANGE_RATE_LIMIT_COUNT:
            messages.error(
                request,
                'Too many failed attempts. Please try again in about 15 minutes.',
            )
            return redirect('students:settings_password')

        form = ChangePasswordForm(user, request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['new_password']
            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)
            request.session.cycle_key()
            cache.delete(cache_key)
            logger.info('Password changed for user_id=%s', user.pk)
            messages.success(
                request,
                'Your password has been changed. You are still logged in on this device.',
            )
            return redirect('students:dashboard')
        else:
            rate_data['count'] = rate_data.get('count', 0) + 1
            cache.set(cache_key, rate_data, PASSWORD_CHANGE_RATE_LIMIT_SECONDS)
    else:
        form = ChangePasswordForm(user)

    return render(request, 'accounts/change_password.html', {
        'form': form,
        'rate_limited': rate_data['count'] >= PASSWORD_CHANGE_RATE_LIMIT_COUNT,
    })


@login_required
def logout_view(request):
    """
    Logout View
    """
    from django.contrib.auth import logout
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('accounts:landing')
