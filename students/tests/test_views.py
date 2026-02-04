"""Tests for students app views."""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from students.models import StudentProfile

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


class StudentDashboardTests(TestCase):
    def test_anonymous_redirects_to_login(self):
        response = Client().get(reverse('students:dashboard'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('accounts:login'), response.url)

    def test_student_sees_dashboard(self):
        make_student()
        c = Client()
        c.login(username='student1', password='testpass123')
        response = c.get(reverse('students:dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_admin_redirected_to_admin_dashboard(self):
        make_admin()
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.get(reverse('students:dashboard'))
        self.assertRedirects(response, reverse('students:admin_dashboard'), fetch_redirect_response=False)


class AdminDashboardTests(TestCase):
    def test_anonymous_redirects_to_login(self):
        response = Client().get(reverse('students:admin_dashboard'))
        self.assertEqual(response.status_code, 302)

    def test_student_cannot_access_admin_dashboard(self):
        make_student()
        c = Client()
        c.login(username='student1', password='testpass123')
        response = c.get(reverse('students:admin_dashboard'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('accounts:login'), response.url)

    def test_admin_sees_dashboard(self):
        make_admin()
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.get(reverse('students:admin_dashboard'))
        self.assertEqual(response.status_code, 200)


class StudentDetailTests(TestCase):
    def setUp(self):
        self.admin = make_admin()
        self.student_user = make_student(username='stu1')
        self.profile = StudentProfile.objects.create(
            user=self.student_user,
            passport_number='',
            address='',
        )

    def test_admin_can_view_student_detail(self):
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.get(reverse('students:student_detail', kwargs={'student_id': self.profile.id}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.student_user.username)

    def test_student_cannot_access_student_detail(self):
        c = Client()
        c.login(username='stu1', password='testpass123')
        response = c.get(reverse('students:student_detail', kwargs={'student_id': self.profile.id}))
        self.assertEqual(response.status_code, 302)

    def test_student_detail_404_for_invalid_id(self):
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.get(reverse('students:student_detail', kwargs={'student_id': 99999}))
        self.assertEqual(response.status_code, 404)


class AdminStudentEditTests(TestCase):
    def setUp(self):
        self.admin = make_admin()
        self.student_user = make_student(username='stu1')
        self.profile = StudentProfile.objects.create(
            user=self.student_user,
            passport_number='P123',
            address='Somewhere',
        )

    def test_edit_page_loads_for_admin(self):
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.get(reverse('students:admin_student_edit', kwargs={'student_id': self.profile.id}))
        self.assertEqual(response.status_code, 200)

    def test_edit_post_redirects_to_confirm(self):
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.post(
            reverse('students:admin_student_edit', kwargs={'student_id': self.profile.id}),
            {
                'first_name': 'Updated',
                'last_name': 'Name',
                'email': 'new@example.com',
                'phone_number': '',
                'is_active': 'on',
                'passport_number': 'P456',
                'address': 'New address',
                'visa_status': 'REGISTERED',
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn('edit/confirm', response.url)

    def test_edit_confirm_apply_updates_record(self):
        c = Client()
        c.login(username='admin1', password='testpass123')
        # First go to edit and submit to set session
        c.post(
            reverse('students:admin_student_edit', kwargs={'student_id': self.profile.id}),
            {
                'first_name': 'Updated',
                'last_name': 'Name',
                'email': 'new@example.com',
                'phone_number': '',
                'is_active': 'on',
                'passport_number': 'P456',
                'address': 'New address',
                'visa_status': 'DOCUMENTS_SUBMITTED',
            },
        )
        response = c.post(
            reverse('students:admin_student_edit_confirm', kwargs={'student_id': self.profile.id}),
            {'confirm': '1'},
        )
        self.assertRedirects(response, reverse('students:student_detail', kwargs={'student_id': self.profile.id}), fetch_redirect_response=False)
        self.profile.refresh_from_db()
        self.student_user.refresh_from_db()
        self.assertEqual(self.profile.passport_number, 'P456')
        self.assertEqual(self.student_user.first_name, 'Updated')

    def test_edit_confirm_cancel_redirects_to_detail(self):
        c = Client()
        c.login(username='admin1', password='testpass123')
        c.post(
            reverse('students:admin_student_edit', kwargs={'student_id': self.profile.id}),
            {
                'first_name': 'X',
                'last_name': 'Y',
                'email': 'x@x.com',
                'phone_number': '',
                'is_active': 'on',
                'passport_number': 'P',
                'address': 'A',
                'visa_status': 'REGISTERED',
            },
        )
        response = c.post(
            reverse('students:admin_student_edit_confirm', kwargs={'student_id': self.profile.id}),
            {'cancel': '1'},
        )
        self.assertRedirects(response, reverse('students:student_detail', kwargs={'student_id': self.profile.id}), fetch_redirect_response=False)


class AdminStudentDeleteTests(TestCase):
    def setUp(self):
        self.admin = make_admin()
        self.student_user = make_student(username='stu1')
        self.profile = StudentProfile.objects.create(
            user=self.student_user,
            passport_number='',
            address='',
        )

    def test_delete_page_loads_for_admin(self):
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.get(reverse('students:admin_student_delete', kwargs={'student_id': self.profile.id}))
        self.assertEqual(response.status_code, 200)

    def test_delete_confirm_removes_user(self):
        c = Client()
        c.login(username='admin1', password='testpass123')
        user_id = self.student_user.id
        response = c.post(
            reverse('students:admin_student_delete', kwargs={'student_id': self.profile.id}),
            {'confirm': '1'},
        )
        self.assertRedirects(response, reverse('students:admin_dashboard'), fetch_redirect_response=False)
        self.assertFalse(User.objects.filter(id=user_id).exists())
        self.assertFalse(StudentProfile.objects.filter(id=self.profile.id).exists())

    def test_delete_cancel_redirects_to_detail(self):
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.post(
            reverse('students:admin_student_delete', kwargs={'student_id': self.profile.id}),
            {'cancel': '1'},
        )
        self.assertRedirects(response, reverse('students:student_detail', kwargs={'student_id': self.profile.id}), fetch_redirect_response=False)
        self.assertTrue(User.objects.filter(username='stu1').exists())


class StudentProfileEditTests(TestCase):
    def setUp(self):
        self.student_user = make_student(username='stu1')
        self.profile = StudentProfile.objects.create(user=self.student_user, passport_number='', address='')

    def test_student_can_edit_own_profile(self):
        c = Client()
        c.login(username='stu1', password='testpass123')
        response = c.get(reverse('students:profile_edit'))
        self.assertEqual(response.status_code, 200)

    def test_admin_redirected_to_dashboard_from_profile_edit(self):
        make_admin()
        c = Client()
        c.login(username='admin1', password='testpass123')
        response = c.get(reverse('students:profile_edit'))
        self.assertRedirects(response, reverse('students:dashboard'), fetch_redirect_response=False)


class URLReverseTests(TestCase):
    """Ensure all student URLs reverse without error."""

    def test_all_student_urls_reverse(self):
        reverse('students:dashboard')
        reverse('students:profile_edit')
        reverse('students:admin_dashboard')
        reverse('students:student_detail', kwargs={'student_id': 1})
        reverse('students:admin_student_edit', kwargs={'student_id': 1})
        reverse('students:admin_student_edit_confirm', kwargs={'student_id': 1})
        reverse('students:admin_student_delete', kwargs={'student_id': 1})
