# Quick Setup Instructions

## Step-by-Step Setup Guide

### 1. Install Dependencies

```bash
# Activate virtual environment (if using one)
# Windows:
venv\Scripts\activate

# Linux/Mac:
source venv/bin/activate

# Install packages
pip install -r requirements.txt
```

### 2. Run Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### 3. Create Admin User

**Option A: Using Django Shell (Recommended)**

```bash
python manage.py shell
```

Then run:
```python
from accounts.models import User
admin = User.objects.create_user(
    username='admin',
    email='admin@fifo-university.com',
    password='admin123',  # Change this!
    first_name='Admin',
    last_name='User',
    role='ADMIN'
)
admin.is_staff = True
admin.is_superuser = True
admin.save()
print("Admin user created successfully!")
exit()
```

**Option B: Using Django Admin**

1. Create superuser:
```bash
python manage.py createsuperuser
```

2. Start server:
```bash
python manage.py runserver
```

3. Go to http://127.0.0.1:8000/admin/
4. Login with superuser credentials
5. Navigate to Users section
6. Find your user and edit it
7. Change "Role" field to "ADMIN"
8. Save

### 4. Create Media Directory

```bash
# Windows
mkdir media

# Linux/Mac
mkdir media
```

### 5. Run Server

```bash
python manage.py runserver
```

### 6. Access the Application

- **Student Registration**: http://127.0.0.1:8000/register/
- **Login**: http://127.0.0.1:8000/login/
- **Admin Dashboard**: http://127.0.0.1:8000/students/admin/dashboard/ (after admin login)
- **Student Dashboard**: http://127.0.0.1:8000/students/dashboard/ (after student login)

## Testing the Application

### Test Student Flow:
1. Register a new student account
2. Login as student
3. Complete profile (add passport number and address)
4. Upload documents
5. Check visa status

### Test Admin Flow:
1. Login as admin
2. View all students in dashboard
3. Click on a student to view details
4. Upload a document for the student
5. Update visa status
6. Check analytics

## Common Issues

### Issue: "No module named 'django'"
**Solution**: Make sure virtual environment is activated and dependencies are installed.

### Issue: "Migration errors"
**Solution**: 
```bash
# Delete db.sqlite3 if it exists
# Then run:
python manage.py makemigrations
python manage.py migrate
```

### Issue: "Media files not showing"
**Solution**: 
- Ensure `media` directory exists
- Check that `MEDIA_ROOT` and `MEDIA_URL` are correctly set in settings.py
- In development, the media files should be served automatically

### Issue: "Admin cannot access admin dashboard"
**Solution**: Ensure the user's role is set to 'ADMIN' in the database.

## Default URLs

- `/` - Redirects to login
- `/register/` - Student registration
- `/login/` - Login page
- `/logout/` - Logout
- `/students/dashboard/` - Student dashboard
- `/students/profile/edit/` - Edit student profile
- `/students/admin/dashboard/` - Admin dashboard
- `/students/admin/student/<id>/` - Student detail (admin only)
- `/documents/upload/` - Upload document (student)
- `/documents/admin/upload/<student_id>/` - Upload document for student (admin)
- `/documents/download/<document_id>/` - Download document
- `/documents/delete/<document_id>/` - Delete document

## Production Checklist

Before deploying to production:

- [ ] Change `SECRET_KEY` in settings.py
- [ ] Set `DEBUG = False`
- [ ] Configure `ALLOWED_HOSTS`
- [ ] Use PostgreSQL or MySQL instead of SQLite
- [ ] Set up proper media file storage (AWS S3, etc.)
- [ ] Enable HTTPS
- [ ] Set up proper logging
- [ ] Configure static files collection
- [ ] Set up backup strategy
- [ ] Use environment variables for sensitive data
- [ ] Set up error monitoring
- [ ] Configure email backend for notifications
