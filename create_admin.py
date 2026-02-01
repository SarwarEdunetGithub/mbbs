#!/usr/bin/env python
"""Script to create admin user"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mbbs_visa.settings')
django.setup()

from accounts.models import User

# Create admin user
try:
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
    print('Admin user created successfully!')
    print('Username: admin')
    print('Password: admin123')
    print('You can now login at: http://127.0.0.1:8000/login/')
except Exception as e:
    print(f'Error: {e}')
    print('Admin user might already exist.')
