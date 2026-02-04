"""Tests for accounts views (login, register, logout, landing)."""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()


class LandingViewTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_landing_anonymous_returns_200(self):
        response = self.client.get(reverse('accounts:landing'))
        self.assertEqual(response.status_code, 200)

    def test_landing_authenticated_student_redirects_to_dashboard(self):
        User.objects.create_user(
            username='s1', password='pass', email='s@x.com', role='STUDENT'
        )
        self.client.login(username='s1', password='pass')
        response = self.client.get(reverse('accounts:landing'))
        self.assertRedirects(response, reverse('students:dashboard'), fetch_redirect_response=False)

    def test_landing_authenticated_admin_redirects_to_admin_dashboard(self):
        u = User.objects.create_user(
            username='a1', password='pass', email='a@x.com', role='ADMIN'
        )
        u.is_staff = True
        u.save()
        self.client.login(username='a1', password='pass')
        response = self.client.get(reverse('accounts:landing'))
        self.assertRedirects(response, reverse('students:admin_dashboard'), fetch_redirect_response=False)


class LoginViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='student1',
            email='s@example.com',
            password='testpass123',
            role='STUDENT'
        )

    def test_login_get_returns_200(self):
        response = self.client.get(reverse('accounts:login'))
        self.assertEqual(response.status_code, 200)

    def test_login_valid_credentials_redirects_student(self):
        response = self.client.post(reverse('accounts:login'), {
            'username': 'student1',
            'password': 'testpass123',
        })
        self.assertRedirects(response, reverse('students:dashboard'), fetch_redirect_response=False)

    def test_login_invalid_credentials_returns_200_with_message(self):
        response = self.client.post(reverse('accounts:login'), {
            'username': 'student1',
            'password': 'wrong',
        })
        self.assertEqual(response.status_code, 200)


class RegisterViewTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_register_get_returns_200(self):
        response = self.client.get(reverse('accounts:register'))
        self.assertEqual(response.status_code, 200)

    def test_register_valid_creates_user_and_redirects(self):
        response = self.client.post(reverse('accounts:register'), {
            'username': 'newuser',
            'email': 'new@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'phone_number': '',
            'password': 'securepass123',
            'password_confirm': 'securepass123',
        })
        self.assertRedirects(response, reverse('accounts:login'), fetch_redirect_response=False)
        self.assertTrue(User.objects.filter(username='newuser').exists())
        self.assertEqual(User.objects.get(username='newuser').role, 'STUDENT')


class LogoutViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        User.objects.create_user(
            username='u1', password='pass', email='u@x.com', role='STUDENT'
        )

    def test_logout_requires_login(self):
        response = self.client.get(reverse('accounts:logout'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('accounts:login'), response.get('Location', ''))

    def test_logout_redirects_after_login(self):
        self.client.login(username='u1', password='pass')
        response = self.client.get(reverse('accounts:logout'))
        self.assertRedirects(response, reverse('accounts:landing'), fetch_redirect_response=False)
