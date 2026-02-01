#!/usr/bin/env python
"""Script to check and fix admin user"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mbbs_visa.settings')
django.setup()

from accounts.models import User

print("Checking admin user...")
print("-" * 40)

# Check if admin exists
try:
    admin = User.objects.get(username='admin')
    print(f"Admin found: {admin.username}")
    print(f"Email: {admin.email}")
    print(f"Role: {admin.role}")
    print(f"Is Staff: {admin.is_staff}")
    print(f"Is Superuser: {admin.is_superuser}")
    print(f"Is Active: {admin.is_active}")
    
    # Reset password to make sure it works
    admin.set_password('admin123')
    admin.role = 'ADMIN'
    admin.is_staff = True
    admin.is_superuser = True
    admin.is_active = True
    admin.save()
    print("-" * 40)
    print("Admin user updated successfully!")
    print("Username: admin")
    print("Password: admin123")
    
except User.DoesNotExist:
    print("Admin user not found. Creating...")
    admin = User.objects.create_user(
        username='admin',
        email='admin@fifo-university.com',
        password='admin123',
        first_name='Admin',
        last_name='User',
        role='ADMIN'
    )
    admin.is_staff = True
    admin.is_superuser = True
    admin.save()
    print("Admin user created!")
    print("Username: admin")
    print("Password: admin123")

print("-" * 40)
print("You can now login at: http://127.0.0.1:8000/login/")
