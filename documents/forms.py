"""
Forms for Document Upload
"""
from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, HTML
from .models import Document


class DocumentUploadForm(forms.ModelForm):
    """
    Document Upload Form for Students
    """
    class Meta:
        model = Document
        fields = ['document_type', 'file', 'title']
        widgets = {
            'document_type': forms.Select(attrs={'class': 'form-control'}),
            'file': forms.FileInput(attrs={'class': 'form-control', 'accept': '.pdf,.jpg,.jpeg,.png'}),
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Optional: Document title'}),
        }
    
    def __init__(self, *args, **kwargs):
        self.student = kwargs.pop('student', None)
        self.uploaded_by = kwargs.pop('uploaded_by', None)
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            'document_type',
            'file',
            'title',
            Submit('submit', 'Upload Document', css_class='btn btn-primary mt-3')
        )
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.student:
            instance.student = self.student
        if self.uploaded_by:
            instance.uploaded_by = self.uploaded_by
        if commit:
            instance.save()
        return instance


class AdminDocumentUploadForm(forms.ModelForm):
    """
    Document Upload Form for Admins
    Allows uploading documents for any student
    """
    class Meta:
        model = Document
        fields = ['document_type', 'file', 'title']
        widgets = {
            'document_type': forms.Select(attrs={'class': 'form-control'}),
            'file': forms.FileInput(attrs={'class': 'form-control', 'accept': '.pdf,.jpg,.jpeg,.png'}),
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Optional: Document title'}),
        }
    
    def __init__(self, *args, **kwargs):
        self.student = kwargs.pop('student', None)
        self.uploaded_by = kwargs.pop('uploaded_by', None)
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            'document_type',
            'file',
            'title',
            Submit('submit', 'Upload Document', css_class='btn btn-primary mt-3')
        )
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.student:
            instance.student = self.student
        if self.uploaded_by:
            instance.uploaded_by = self.uploaded_by
        if commit:
            instance.save()
        return instance
