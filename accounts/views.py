"""
Authentication Views: Login, Register, Logout, Landing Page, Change Password, Forgot Password
"""
import logging
import secrets
import string
import time
from datetime import timedelta
from django.shortcuts import render, redirect
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


def _generate_temporary_password(length=14):
    """Strong random password: mixed classes, 12+ chars. Never log this."""
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
            user = form.save(commit=False)
            user.role = 'STUDENT'
            user.set_password(form.cleaned_data['password'])
            user.save()
            
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
    If user logs in with a temporary password (forgot-password flow), invalidate it
    and redirect to force-change-password.
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
    Forgot password: email and/or phone. Non-enumeration (always generic success).
    Rate limit: per-user 2/day, per-IP 10/hour. Audit log; send SMS/email via adapters.
    """
    if request.user.is_authenticated:
        return redirect('students:dashboard')

    ip = _get_client_ip(request)
    user_agent = _get_user_agent(request)
    max_per_ip = getattr(settings, 'PASSWORD_RESET_MAX_PER_IP_PER_HOUR', 10)
    max_per_user = getattr(settings, 'PASSWORD_RESET_MAX_PER_USER_PER_DAY', 2)
    valid_minutes = getattr(settings, 'PASSWORD_RESET_TEMP_VALID_MINUTES', 15)

    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            # Per-IP throttle
            ip_key = f'pwd_reset_ip:{ip}'
            ip_count = cache.get(ip_key, 0)
            if ip_count >= max_per_ip:
                time.sleep(FORGOT_PASSWORD_RESPONSE_DELAY)
                PasswordResetAuditLog.objects.create(
                    user=None,
                    ip_address=ip,
                    user_agent=user_agent,
                    result=PasswordResetAuditLog.RESULT_RATE_LIMIT_IP,
                )
                messages.success(
                    request,
                    'If an account exists with that email or phone, you will receive instructions shortly. Please check your inbox and messages.',
                )
                return render(request, 'accounts/forgot_password.html', {'form': ForgotPasswordForm()})

            email = form.cleaned_data.get('email')
            phone = form.cleaned_data.get('phone')
            user = None
            if email:
                user = User.objects.filter(email__iexact=email, role='STUDENT').first()
            if user is None and phone:
                phone_clean = ''.join(c for c in phone if c.isdigit())
                if phone_clean:
                    user = User.objects.filter(phone_number__icontains=phone_clean, role='STUDENT').first()

            if user is not None:
                today = timezone.now().date()
                count_today = PasswordResetAuditLog.objects.filter(
                    user=user,
                    requested_at__date=today,
                    result=PasswordResetAuditLog.RESULT_SENT,
                ).count()
                if count_today >= max_per_user:
                    time.sleep(FORGOT_PASSWORD_RESPONSE_DELAY)
                    cache.set(ip_key, ip_count + 1, 3600)
                    PasswordResetAuditLog.objects.create(
                        user=user,
                        ip_address=ip,
                        user_agent=user_agent,
                        email_attempted=False,
                        sms_attempted=False,
                        result=PasswordResetAuditLog.RESULT_RATE_LIMIT_USER,
                    )
                    messages.success(
                        request,
                        'If an account exists with that email or phone, you will receive instructions shortly. Please check your inbox and messages.',
                    )
                    return render(request, 'accounts/forgot_password.html', {'form': ForgotPasswordForm()})

                # Invalidate any previous temp password
                user.temp_password_expires_at = None
                user.save(update_fields=['temp_password_expires_at'])
                temp_password = _generate_temporary_password()
                user.set_password(temp_password)
                expires_at = timezone.now() + timedelta(minutes=valid_minutes)
                user.temp_password_expires_at = expires_at
                user.save(update_fields=['password', 'temp_password_expires_at'])

                email_ok = False
                sms_ok = False
                if getattr(settings, 'SEND_EMAIL_ENABLED', True) and user.email:
                    body = f'Your temporary password is: {temp_password}\nIt is valid for {valid_minutes} minutes and can only be used once. After logging in you will be asked to set a new password.'
                    email_ok = send_email(user.email, 'Password reset - Aspire Abroad', body)
                if getattr(settings, 'SEND_SMS_ENABLED', False) and user.phone_number:
                    msg = f'Aspire Abroad: Your one-time password is {temp_password}. Valid for {valid_minutes} min. Set a new password after login.'
                    sms_ok = send_sms(user.phone_number, msg)

                PasswordResetAuditLog.objects.create(
                    user=user,
                    ip_address=ip,
                    user_agent=user_agent,
                    email_attempted=bool(user.email),
                    email_success=email_ok,
                    sms_attempted=bool(user.phone_number),
                    sms_success=sms_ok,
                    result=PasswordResetAuditLog.RESULT_SENT,
                )
                cache.set(ip_key, ip_count + 1, 3600)
            else:
                PasswordResetAuditLog.objects.create(
                    user=None,
                    ip_address=ip,
                    user_agent=user_agent,
                    result=PasswordResetAuditLog.RESULT_NO_MATCH,
                )
                cache.set(ip_key, ip_count + 1, 3600)

            time.sleep(FORGOT_PASSWORD_RESPONSE_DELAY)
            messages.success(
                request,
                'If an account exists with that email or phone, you will receive instructions shortly. Please check your inbox and messages.',
            )
            return render(request, 'accounts/forgot_password.html', {'form': ForgotPasswordForm()})
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
