"""
Tests for forgot-password flow: happy path, rate limits, expired temp, non-existing user,
SMS/email failure handling, one-time use.
"""
from unittest.mock import patch
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.core.cache import cache

from accounts.models import PasswordResetAuditLog

User = get_user_model()


def make_student(**kwargs):
    defaults = {
        'username': 'student1',
        'email': 's@example.com',
        'password': 'testpass123',
        'role': 'STUDENT',
        'phone_number': '9876543210',
    }
    defaults.update(kwargs)
    user = User.objects.create_user(**defaults)
    return user


@override_settings(
    SEND_EMAIL_ENABLED=False,
    SEND_SMS_ENABLED=False,
    PASSWORD_RESET_MAX_PER_USER_PER_DAY=2,
    PASSWORD_RESET_MAX_PER_IP_PER_HOUR=10,
    PASSWORD_RESET_TEMP_VALID_MINUTES=15,
)
class ForgotPasswordViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        cache.clear()

    def test_get_returns_200(self):
        response = self.client.get(reverse('auth:forgot_password'))
        self.assertEqual(response.status_code, 200)

    def test_non_existing_user_generic_success(self):
        """Non-existing user must still show generic success (non-enumeration)."""
        response = self.client.post(reverse('auth:forgot_password'), {
            'email': 'nonexistent@example.com',
            'phone': '',
        })
        self.assertEqual(response.status_code, 200)
        messages = list(response.context.get('messages', []))
        self.assertTrue(any('instructions' in str(m).lower() or 'receive' in str(m).lower() for m in messages))
        self.assertEqual(PasswordResetAuditLog.objects.filter(result=PasswordResetAuditLog.RESULT_NO_MATCH).count(), 1)

    @patch('accounts.views.send_email', return_value=True)
    @patch('accounts.views.send_sms', return_value=True)
    def test_happy_path_sends_and_audit(self, mock_sms, mock_email):
        user = make_student()
        response = self.client.post(reverse('auth:forgot_password'), {
            'email': user.email,
            'phone': user.phone_number or '',
        })
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertIsNotNone(user.temp_password_expires_at)
        log = PasswordResetAuditLog.objects.get(user=user, result=PasswordResetAuditLog.RESULT_SENT)
        self.assertTrue(log.email_attempted or log.sms_attempted)

    @override_settings(PASSWORD_RESET_MAX_PER_USER_PER_DAY=2)
    def test_third_attempt_same_day_generic_success(self):
        """3rd request same day for same user hits per-user limit; still generic message."""
        user = make_student()
        url = reverse('auth:forgot_password')
        for _ in range(2):
            with patch('accounts.views.send_email', return_value=True):
                self.client.post(url, {'email': user.email, 'phone': ''})
        response = self.client.post(url, {'email': user.email, 'phone': ''})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            PasswordResetAuditLog.objects.filter(user=user, result=PasswordResetAuditLog.RESULT_RATE_LIMIT_USER).count(),
            1,
        )

    def test_expired_temp_password_rejected_at_login(self):
        user = make_student()
        user.temp_password_expires_at = timezone.now() - timedelta(minutes=1)
        user.set_password('TempPass123!')
        user.save(update_fields=['password', 'temp_password_expires_at'])
        response = self.client.post(reverse('auth:login'), {
            'username': user.username,
            'password': 'TempPass123!',
            'remember_me': 'on',
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'expired', response.content.lower())
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    @patch('accounts.views.send_email', return_value=False)
    @patch('accounts.views.send_sms', return_value=False)
    def test_sms_email_failure_still_audit_and_success(self, mock_sms, mock_email):
        """When both channels fail, we still record audit and show generic success."""
        user = make_student()
        response = self.client.post(reverse('auth:forgot_password'), {
            'email': user.email,
            'phone': '',
        })
        self.assertEqual(response.status_code, 200)
        log = PasswordResetAuditLog.objects.get(user=user, result=PasswordResetAuditLog.RESULT_SENT)
        self.assertTrue(log.email_attempted)
        self.assertFalse(log.email_success)

    def test_one_time_use_after_login_redirects_to_force_change(self):
        user = make_student()
        user.set_password('TempPass123!ab')
        user.temp_password_expires_at = timezone.now() + timedelta(minutes=15)
        user.save(update_fields=['password', 'temp_password_expires_at'])
        response = self.client.post(reverse('auth:login'), {
            'username': user.username,
            'password': 'TempPass123!ab',
            'remember_me': 'on',
        })
        self.assertRedirects(response, reverse('auth:force_change_password'), fetch_redirect_response=False)
        user.refresh_from_db()
        self.assertIsNone(user.temp_password_expires_at)
        self.assertTrue(self.client.session.get('must_change_password'))

    def test_force_change_clears_session_and_sets_password(self):
        user = make_student()
        user.set_password('x')
        user.save()
        self.client.force_login(user)
        session = self.client.session
        session['must_change_password'] = True
        session.save()
        response = self.client.post(reverse('auth:force_change_password'), {
            'new_password': 'NewSecurePass123!',
            'new_password_confirm': 'NewSecurePass123!',
        })
        self.assertRedirects(response, reverse('students:dashboard'), fetch_redirect_response=False)
        self.assertNotIn('must_change_password', self.client.session)
        user.refresh_from_db()
        self.assertTrue(user.check_password('NewSecurePass123!'))

    def test_form_requires_email_or_phone(self):
        response = self.client.post(reverse('auth:forgot_password'), {'email': '', 'phone': ''})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['form'].errors)
