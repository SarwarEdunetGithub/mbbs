"""
Document Views: Upload, View, Download
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import FileResponse, Http404
from django.conf import settings
import os
from .models import Document
from .forms import DocumentUploadForm, AdminDocumentUploadForm
from students.models import StudentProfile


def is_admin(user):
    """Check if user is admin"""
    return user.is_authenticated and user.is_admin()


@login_required
def document_upload(request):
    """
    Student Document Upload View
    """
    if not request.user.is_student():
        return redirect('students:dashboard')
    
    if request.method == 'POST':
        form = DocumentUploadForm(
            request.POST,
            request.FILES,
            student=request.user,
            uploaded_by=request.user
        )
        if form.is_valid():
            document = form.save()
            
            # Update visa status if first document upload
            profile, created = StudentProfile.objects.get_or_create(user=request.user)
            if profile.visa_status == 'REGISTERED':
                profile.visa_status = 'DOCUMENTS_SUBMITTED'
                profile.save()
            
            messages.success(request, 'Document uploaded successfully!')
            return redirect('students:dashboard')
    else:
        form = DocumentUploadForm(student=request.user, uploaded_by=request.user)
    
    return render(request, 'documents/upload.html', {'form': form})


@login_required
@user_passes_test(is_admin)
def admin_document_upload(request, student_id):
    """
    Admin Document Upload View
    Upload documents for a specific student
    Note: student_id here refers to StudentProfile.id, not User.id
    """
    from students.models import StudentProfile
    student_profile = get_object_or_404(StudentProfile, id=student_id)
    student = student_profile.user
    
    if request.method == 'POST':
        form = AdminDocumentUploadForm(
            request.POST,
            request.FILES,
            student=student,
            uploaded_by=request.user
        )
        if form.is_valid():
            form.save()
            messages.success(
                request,
                f'Document uploaded successfully for {student.get_full_name() or student.username}!'
            )
            return redirect('students:student_detail', student_id=student_profile.id)
    else:
        form = AdminDocumentUploadForm(student=student, uploaded_by=request.user)
    
    return render(request, 'documents/admin_upload.html', {
        'form': form,
        'student': student,
        'student_profile': student_profile
    })


@login_required
@user_passes_test(is_admin)
def document_view(request, document_id):
    """
    Admin only: View/Preview document before downloading
    """
    document = get_object_or_404(Document, id=document_id)
    
    # Determine if we can preview in browser (PDF, images)
    filename = document.filename().lower()
    is_previewable = (
        filename.endswith('.pdf') or
        filename.endswith('.jpg') or filename.endswith('.jpeg') or
        filename.endswith('.png') or filename.endswith('.gif') or filename.endswith('.webp')
    )
    is_pdf = filename.endswith('.pdf')
    
    # Get student profile id for back link
    try:
        profile_id = document.student.student_profile.id
    except Exception:
        profile_id = None
    
    context = {
        'document': document,
        'is_previewable': is_previewable,
        'is_pdf': is_pdf,
        'profile_id': profile_id,
    }
    
    return render(request, 'documents/view.html', context)


@login_required
def document_download(request, document_id):
    """
    Document Download View
    Students can download their own documents
    Admins can download any document
    """
    document = get_object_or_404(Document, id=document_id)
    
    # Permission check
    if not (request.user.is_admin() or document.student == request.user):
        messages.error(request, 'You do not have permission to access this document.')
        return redirect('students:dashboard')
    
    # Check if file exists
    if document.file and os.path.exists(document.file.path):
        try:
            response = FileResponse(
                open(document.file.path, 'rb'),
                content_type='application/octet-stream'
            )
            response['Content-Disposition'] = f'attachment; filename="{document.filename()}"'
            return response
        except Exception as e:
            messages.error(request, f'Error downloading file: {str(e)}')
            return redirect('students:dashboard')
    else:
        messages.error(request, 'File not found.')
        return redirect('students:dashboard')


@login_required
def document_delete(request, document_id):
    """
    Document Delete View
    Students can delete their own documents
    Admins can delete any document
    """
    document = get_object_or_404(Document, id=document_id)
    
    # Permission check
    if not (request.user.is_admin() or document.student == request.user):
        messages.error(request, 'You do not have permission to delete this document.')
        return redirect('students:dashboard')
    
    if request.method == 'POST':
        student_id = document.student.id
        document.delete()
        messages.success(request, 'Document deleted successfully!')
        
        if request.user.is_admin():
            return redirect('students:student_detail', student_id=student_id)
        else:
            return redirect('students:dashboard')
    
    return render(request, 'documents/delete_confirm.html', {'document': document})
