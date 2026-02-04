"""
Pluggable SMS/Email adapters for password reset. Stub implementations;
replace with real providers (e.g. Twilio, SendGrid) and use env toggles.
"""
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


def send_email(to: str, subject: str, body: str) -> bool:
    """
    Send an email. Returns True if sent successfully.
    Uses SEND_EMAIL_ENABLED from settings; stub logs and returns True when disabled.
    """
    if not getattr(settings, 'SEND_EMAIL_ENABLED', True):
        logger.info('Email not sent (disabled): to=%s subject=%s', to, subject)
        return False
    try:
        from django.core.mail import send_mail
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None) or 'noreply@aspireabroad.example'
        send_mail(
            subject=subject,
            message=body,
            from_email=from_email,
            recipient_list=[to],
            fail_silently=False,
        )
        return True
    except Exception as e:
        logger.warning('Email send failed: to=%s error=%s', to, e)
        return False


def send_sms(to: str, message: str) -> bool:
    """
    Send an SMS. Returns True if sent successfully.
    Uses SEND_SMS_ENABLED from settings; stub logs and returns False when disabled.
    """
    if not getattr(settings, 'SEND_SMS_ENABLED', False):
        logger.info('SMS not sent (disabled): to=%s', to)
        return False
    try:
        # Stub: integrate with Twilio, AWS SNS, etc.
        logger.info('SMS stub: to=%s message_len=%d', to, len(message))
        return True
    except Exception as e:
        logger.warning('SMS send failed: to=%s error=%s', to, e)
        return False
