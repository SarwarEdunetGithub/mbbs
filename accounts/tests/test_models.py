"""Tests for accounts models."""
from django.test import TestCase
from django.contrib.auth import get_user_model

User = get_user_model()


class UserModelTests(TestCase):
    """Test User model and role helpers."""

    def test_create_student_user(self):
        user = User.objects.create_user(
            username='student1',
            email='s@example.com',
            password='testpass123',
            role='STUDENT'
        )
        self.assertEqual(user.role, 'STUDENT')
        self.assertTrue(user.is_student())
        self.assertFalse(user.is_admin())

    def test_create_admin_user(self):
        user = User.objects.create_user(
            username='admin1',
            email='a@example.com',
            password='testpass123',
            role='ADMIN'
        )
        user.is_staff = True
        user.save()
        self.assertTrue(user.is_admin())
        self.assertFalse(user.is_student())

    def test_staff_user_treated_as_admin(self):
        """Staff/superuser without role=ADMIN still get admin access."""
        user = User.objects.create_user(
            username='staff1',
            email='staff@example.com',
            password='testpass123',
            role='STUDENT'
        )
        user.is_staff = True
        user.save()
        self.assertTrue(user.is_admin())

    def test_superuser_gets_admin_role(self):
        user = User.objects.create_superuser(
            username='super1',
            email='super@example.com',
            password='testpass123'
        )
        self.assertEqual(user.role, 'ADMIN')
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_admin())
