import os
import django
from django.conf import settings
from django.core.mail import send_mail

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mbbs_visa.settings')
django.setup()

def verify_email():
    try:
        print(f"Testing email configuration...")
        print(f"Host: {settings.EMAIL_HOST}")
        print(f"User: {settings.EMAIL_HOST_USER}")
        
        send_mail(
            subject='Test Email from Aspire Abroad',
            message='This is a test email to verify SMTP configuration.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[settings.EMAIL_HOST_USER], # Send to self
            fail_silently=False,
        )
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

if __name__ == '__main__':
    verify_email()
