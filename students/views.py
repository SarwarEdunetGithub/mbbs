"""
Student and Admin Views
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.db.models import Count, Q
from django.core.paginator import Paginator
from .models import StudentProfile
from .forms import StudentProfileForm, VisaStatusUpdateForm
from documents.models import Document


def is_admin(user):
    """Check if user is admin"""
    return user.is_authenticated and user.is_admin()


@login_required
def student_dashboard(request):
    """
    Student Dashboard
    Shows profile, documents, and visa status
    """
    if not request.user.is_student():
        return redirect('students:admin_dashboard')
    
    # Get or create student profile
    profile, created = StudentProfile.objects.get_or_create(
        user=request.user,
        defaults={
            'passport_number': '',
            'address': '',
        }
    )
    
    # Get all documents for this student
    student_documents = Document.objects.filter(student=request.user).order_by('-uploaded_at')
    
    # Count documents by type
    document_counts = student_documents.values('document_type').annotate(
        count=Count('id')
    )
    
    context = {
        'profile': profile,
        'documents': student_documents,
        'document_counts': document_counts,
        'total_documents': student_documents.count(),
    }
    
    return render(request, 'students/dashboard.html', context)


@login_required
def student_profile_edit(request):
    """
    Student Profile Edit View with photo upload
    """
    if not request.user.is_student():
        return redirect('students:dashboard')
    
    profile, created = StudentProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        form = StudentProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('students:dashboard')
    else:
        form = StudentProfileForm(instance=profile)
    
    return render(request, 'students/profile_edit.html', {'form': form, 'profile': profile})


@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    """
    Admin Dashboard
    Shows all students, analytics, documents view, and quick actions
    """
    # Get all students
    students = StudentProfile.objects.select_related('user').all().order_by('-created_at')
    
    # Get recent documents across all students (with student profile id for links)
    docs = Document.objects.select_related('student', 'uploaded_by').order_by('-uploaded_at')[:20]
    recent_documents = []
    for doc in docs:
        try:
            profile_id = doc.student.student_profile.id
        except Exception:
            profile_id = None
        recent_documents.append({'doc': doc, 'profile_id': profile_id})
    
    # Document count per student (for students table)
    students_with_doc_count = StudentProfile.objects.select_related('user').annotate(
        document_count=Count('user__documents')
    ).order_by('-created_at')
    
    # Analytics
    total_students = students.count()
    approved_count = students.filter(visa_status='APPROVED').count()
    pending_count = students.filter(
        Q(visa_status='REGISTERED') | 
        Q(visa_status='DOCUMENTS_SUBMITTED') | 
        Q(visa_status='UNDER_REVIEW')
    ).count()
    rejected_count = students.filter(visa_status='REJECTED').count()
    
    # Status breakdown
    status_breakdown = students.values('visa_status').annotate(
        count=Count('id')
    ).order_by('visa_status')
    
    # Pagination for students
    paginator = Paginator(students_with_doc_count, 10)  # 10 students per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'students': page_obj,
        'recent_documents': recent_documents,
        'total_students': total_students,
        'approved_count': approved_count,
        'pending_count': pending_count,
        'rejected_count': rejected_count,
        'status_breakdown': status_breakdown,
    }
    
    return render(request, 'students/admin_dashboard.html', context)


@login_required
@user_passes_test(is_admin)
def student_detail(request, student_id):
    """
    Admin view: Detailed view of a student
    """
    student = get_object_or_404(StudentProfile, id=student_id)
    documents = Document.objects.filter(student=student.user).order_by('-uploaded_at')
    
    # Status update form
    if request.method == 'POST' and 'update_status' in request.POST:
        status_form = VisaStatusUpdateForm(request.POST, instance=student)
        if status_form.is_valid():
            status_form.save()
            messages.success(request, f'Visa status updated to {student.get_visa_status_display()}')
            return redirect('students:student_detail', student_id=student_id)
    else:
        status_form = VisaStatusUpdateForm(instance=student)
    
    context = {
        'student': student,
        'documents': documents,
        'status_form': status_form,
    }
    
    return render(request, 'students/student_detail.html', context)
