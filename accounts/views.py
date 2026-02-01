"""
Authentication Views: Login, Register, Logout, Landing Page
"""
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from .forms import StudentRegistrationForm, LoginForm


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
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                if user.is_active:
                    login(request, user)
                    messages.success(request, f'Welcome, {user.get_full_name() or user.username}!')
                    
                    # Redirect based on role
                    if user.is_admin():
                        return redirect('students:admin_dashboard')
                    else:
                        return redirect('students:dashboard')
                else:
                    messages.error(request, 'Your account has been disabled.')
            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    
    return render(request, 'accounts/login.html', {'form': form})


@login_required
def logout_view(request):
    """
    Logout View
    """
    from django.contrib.auth import logout
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('accounts:landing')
