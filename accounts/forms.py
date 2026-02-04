"""
Forms for Authentication
"""
from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.password_validation import validate_password
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column, Submit, HTML
from .models import User


class ChangePasswordForm(forms.Form):
    """
    Secure change-password form: current password, new password, confirm.
    Requires the requesting user to be passed in to verify current password.
    Runs Django's AUTH_PASSWORD_VALIDATORS on the new password.
    """
    current_password = forms.CharField(
        label='Current password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your current password',
            'autocomplete': 'current-password',
        }),
        required=True,
    )
    new_password = forms.CharField(
        label='New password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new password',
            'autocomplete': 'new-password',
        }),
        required=True,
        help_text='At least 8 characters; avoid common or purely numeric passwords.',
    )
    new_password_confirm = forms.CharField(
        label='Confirm new password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Re-enter new password',
            'autocomplete': 'new-password',
        }),
        required=True,
        help_text='Must match the new password above.',
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        value = self.cleaned_data.get('current_password')
        if value and not self.user.check_password(value):
            raise forms.ValidationError('The current password is incorrect.')
        return value

    def clean_new_password(self):
        value = self.cleaned_data.get('new_password')
        if value:
            validate_password(value, self.user)
        return value

    def clean(self):
        cleaned = super().clean()
        new = cleaned.get('new_password')
        confirm = cleaned.get('new_password_confirm')
        if new and confirm and new != confirm:
            self.add_error('new_password_confirm', 'The two new password fields did not match.')
        return cleaned


class ForgotPasswordForm(forms.Form):
    """Forgot password: at least one of email or phone required (non-enumeration)."""
    email = forms.EmailField(
        required=False,
        label='Email',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your registered email',
            'autocomplete': 'email',
        }),
    )
    phone = forms.CharField(
        required=False,
        max_length=15,
        label='Phone number',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your registered phone',
            'autocomplete': 'tel',
        }),
    )

    def clean(self):
        cleaned = super().clean()
        email = (cleaned.get('email') or '').strip()
        phone = (cleaned.get('phone') or '').strip()
        if not email and not phone:
            raise forms.ValidationError('Please enter your email or phone number (or both).')
        cleaned['email'] = email or None
        cleaned['phone'] = phone or None
        return cleaned


class ForceChangePasswordForm(forms.Form):
    """Mandatory password change after temp-password login (no current password)."""
    new_password = forms.CharField(
        label='New password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Choose a new password',
            'autocomplete': 'new-password',
        }),
        required=True,
        help_text='At least 8 characters; avoid common or purely numeric passwords.',
    )
    new_password_confirm = forms.CharField(
        label='Confirm new password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Re-enter new password',
            'autocomplete': 'new-password',
        }),
        required=True,
        help_text='Must match the new password above.',
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_new_password(self):
        value = self.cleaned_data.get('new_password')
        if value:
            validate_password(value, self.user)
        return value

    def clean(self):
        cleaned = super().clean()
        new = cleaned.get('new_password')
        confirm = cleaned.get('new_password_confirm')
        if new and confirm and new != confirm:
            self.add_error('new_password_confirm', 'The two password fields did not match.')
        return cleaned


class StudentRegistrationForm(forms.ModelForm):
    """
    Student Registration Form
    """
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        min_length=8,
        help_text='Password must be at least 8 characters long.'
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        label='Confirm Password',
        help_text='Enter the same password as before, for verification.'
    )
    
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'phone_number', 'password']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Row(
                Column('username', css_class='form-group col-md-6 mb-3'),
                Column('email', css_class='form-group col-md-6 mb-3'),
            ),
            Row(
                Column('first_name', css_class='form-group col-md-6 mb-3'),
                Column('last_name', css_class='form-group col-md-6 mb-3'),
            ),
            Row(
                Column('phone_number', css_class='form-group col-md-6 mb-3'),
            ),
            Row(
                Column('password', css_class='form-group col-md-6 mb-3'),
                Column('password_confirm', css_class='form-group col-md-6 mb-3'),
            ),
            Submit('submit', 'Register', css_class='btn btn-primary w-100 mt-3')
        )
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('A user with this email already exists.')
        return email
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('A user with this username already exists.')
        return username
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        
        if password and password_confirm:
            if password != password_confirm:
                raise forms.ValidationError({
                    'password_confirm': 'Passwords do not match.'
                })
        
        return cleaned_data


class LoginForm(forms.Form):
    """
    Login Form – used with manual template markup for labels, helper text, password toggle.
    """
    username = forms.CharField(
        max_length=150,
        label='Username',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your username',
            'autocomplete': 'username',
            'autocapitalize': 'none',
        })
    )
    password = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password',
            'autocomplete': 'current-password',
        })
    )
    remember_me = forms.BooleanField(
        required=False,
        initial=True,
        label='Remember me',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
