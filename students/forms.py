"""
Forms for Student Profile
"""
from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column, Submit
from .models import StudentProfile


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
