"""
Authentication Views: Login, Register, Logout, Landing Page, Change Password
"""
import logging
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from .forms import StudentRegistrationForm, LoginForm, ChangePasswordForm

logger = logging.getLogger(__name__)

# Rate limit for change-password failures (no extra frameworks)
PASSWORD_CHANGE_RATE_LIMIT_COUNT = 5
PASSWORD_CHANGE_RATE_LIMIT_SECONDS = 900  # 15 minutes


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
    Login View for both Students and Admins
    Redirects to appropriate dashboard based on role
    """
    if request.user.is_authenticated:
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
                    login(request, user)
                    if not remember_me:
                        request.session.set_expiry(0)  # session when browser closes
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
    """Placeholder: instruct user to contact support for password reset."""
    return render(request, 'accounts/forgot_password.html')


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
