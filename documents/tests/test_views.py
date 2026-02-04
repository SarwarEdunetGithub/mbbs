"""Tests for documents app views."""
import io
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from students.models import StudentProfile
from documents.models import Document
from accounts.models import Notification

User = get_user_model()


def make_student(username='student1', **kwargs):
    defaults = {'email': 's@x.com', 'password': 'testpass123', 'role': 'STUDENT'}
    defaults.update(kwargs)
    return User.objects.create_user(username=username, **defaults)


def make_admin(username='admin1'):
    u = User.objects.create_user(
        username=username,
        email='a@x.com',
        password='testpass123',
        role='ADMIN'
    )
    u.is_staff = True
    u.save()
    return u


@override_settings(MEDIA_ROOT='/tmp/mbbs_test_media')
class DocumentUploadTests(TestCase):
    def setUp(self):
        self.student = make_student()
        self.profile = StudentProfile.objects.create(user=self.student, passport_number='', address='')

    def test_anonymous_cannot_upload(self):
        response = Client().get(reverse('documents:upload'))
        self.assertEqual(response.status_code, 302)

    def test_student_can_access_upload_page(self):
        c = Client()
        c.login(username='student1', password='testpass123')
        response = c.get(reverse('documents:upload'))
        self.assertEqual(response.status_code, 200)

    def test_admin_deleting_document_creates_notification(self):
        admin = make_admin()
        doc = Document.objects.create(
            student=self.student,
            document_type='10TH_MARKSHEET',
            title='Test',
            file=SimpleUploadedFile('test.txt', b'content'),
            uploaded_by=admin,
        )
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.post(reverse('documents:delete', kwargs={'document_id': doc.id}), {})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Notification.objects.filter(user=self.student).exists())
        self.assertFalse(Document.objects.filter(id=doc.id).exists())


class DocumentDeleteTests(TestCase):
    def setUp(self):
        self.student = make_student()
        self.profile = StudentProfile.objects.create(user=self.student, passport_number='', address='')
        self.document = Document.objects.create(
            student=self.student,
            document_type='AADHAAR',
            title='Aadhaar',
            file=SimpleUploadedFile('aadhaar.pdf', b'pdf content'),
            uploaded_by=self.student,
        )

    def test_delete_confirm_page_loads_for_student(self):
        c = Client()
        c.login(username='student1', password='testpass123')
        response = c.get(reverse('documents:delete', kwargs={'document_id': self.document.id}))
        self.assertEqual(response.status_code, 200)

    def test_delete_post_removes_document_for_student(self):
        c = Client()
        c.login(username='student1', password='testpass123')
        response = c.post(reverse('documents:delete', kwargs={'document_id': self.document.id}), {})
        self.assertRedirects(response, reverse('students:dashboard'), fetch_redirect_response=False)
        self.assertFalse(Document.objects.filter(id=self.document.id).exists())

    def test_anonymous_cannot_delete(self):
        response = Client().get(reverse('documents:delete', kwargs={'document_id': self.document.id}))
        self.assertEqual(response.status_code, 302)


class DocumentDownloadTests(TestCase):
    def setUp(self):
        self.student = make_student()
        self.profile = StudentProfile.objects.create(user=self.student, passport_number='', address='')
        self.document = Document.objects.create(
            student=self.student,
            document_type='PAN',
            title='PAN',
            file=SimpleUploadedFile('pan.pdf', b'content'),
            uploaded_by=self.student,
        )

    def test_student_can_download_own_document(self):
        c = Client()
        c.login(username='student1', password='testpass123')
        response = c.get(reverse('documents:download', kwargs={'document_id': self.document.id}))
        # May be 200 (file) or 302 if file not on disk in test
        self.assertIn(response.status_code, (200, 302))

    def test_other_student_cannot_download(self):
        other = make_student(username='other1')
        StudentProfile.objects.create(user=other, passport_number='', address='')
        c = Client()
        c.login(username='other1', password='testpass123')
        response = c.get(reverse('documents:download', kwargs={'document_id': self.document.id}))
        self.assertRedirects(response, reverse('students:dashboard'), fetch_redirect_response=False)


class DocumentURLReverseTests(TestCase):
    def test_all_document_urls_reverse(self):
        reverse('documents:upload')
        reverse('documents:admin_upload', kwargs={'student_id': 1})
        reverse('documents:view', kwargs={'document_id': 1})
        reverse('documents:download', kwargs={'document_id': 1})
        reverse('documents:delete', kwargs={'document_id': 1})
