"""
Forms for Student Profile
"""
from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column, Submit
from .models import StudentProfile
from accounts.models import User


class StudentProfileForm(forms.ModelForm):
    """
    Student Profile Form with photo upload
    """
    class Meta:
        model = StudentProfile
        fields = ['photo', 'passport_number', 'address']
        widgets = {
            'photo': forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'}),
            'passport_number': forms.TextInput(attrs={'class': 'form-control'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_enctype = 'multipart/form-data'
        self.helper.layout = Layout(
            'photo',
            'passport_number',
            'address',
            Submit('submit', 'Save Profile', css_class='btn btn-primary mt-3')
        )


class VisaStatusUpdateForm(forms.ModelForm):
    """
    Admin form to update visa status
    """
    class Meta:
        model = StudentProfile
        fields = ['visa_status']
        widgets = {
            'visa_status': forms.Select(attrs={'class': 'form-control'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            'visa_status',
            Submit('submit', 'Update Status', css_class='btn btn-primary mt-3')
        )


class AdminUserUpdateForm(forms.ModelForm):
    """
    Admin form to update a student's User record (account details).
    """
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'is_active']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
        }


class AdminStudentProfileUpdateForm(forms.ModelForm):
    """
    Admin form to update a student's profile record.
    (No photo field here to keep confirmation workflow simple.)
    """
    class Meta:
        model = StudentProfile
        fields = ['passport_number', 'address', 'visa_status']
        widgets = {
            'passport_number': forms.TextInput(attrs={'class': 'form-control'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'visa_status': forms.Select(attrs={'class': 'form-control'}),
        }
