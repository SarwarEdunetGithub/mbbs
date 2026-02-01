# MBBS Visa Management System - FIFO University (Russia)

A complete, production-ready web application for managing student registrations and documents required for MBBS (5 years) visa processing for Russia.

## Features

### Student Features
- ✅ Student registration with complete visa-required details
- ✅ Secure login system
- ✅ Responsive student dashboard
- ✅ Document upload (10th Marksheet, 12th Marksheet, Aadhaar Card, PAN Card, Additional documents)
- ✅ View and download uploaded documents
- ✅ View documents uploaded by Admin
- ✅ Visa status tracking (Registered → Documents Submitted → Under Review → Approved → Rejected)

### Admin Features
- ✅ Secure admin login (no public registration)
- ✅ Admin dashboard with analytics
- ✅ View all registered students in a table
- ✅ View full student profile details
- ✅ View and download student documents
- ✅ Upload additional documents for students
- ✅ Update visa status
- ✅ Analytics dashboard (Total students, Approved, Pending, Rejected)

## Technology Stack

- **Backend**: Django 5.0.1 (Latest LTS)
- **Database**: SQLite3
- **Frontend**: Django Templates with Bootstrap 5
- **Styling**: Bootstrap 5 + Custom CSS
- **Forms**: Django Crispy Forms
- **File Handling**: Django FileField with secure uploads

## Project Structure

```
mbbs/
├── accounts/              # User authentication and custom user model
│   ├── models.py         # Custom User model with Student/Admin roles
│   ├── views.py          # Login, Register, Logout views
│   ├── forms.py          # Registration and login forms
│   └── urls.py           # Authentication URLs
│
├── students/             # Student profile and management
│   ├── models.py         # StudentProfile model
│   ├── views.py          # Student and Admin dashboards
│   ├── forms.py          # Profile and status update forms
│   └── urls.py           # Student URLs
│
├── documents/            # Document upload and management
│   ├── models.py         # Document model
│   ├── views.py          # Upload, download, delete views
│   ├── forms.py          # Document upload forms
│   └── urls.py           # Document URLs
│
├── templates/            # HTML templates
│   ├── base.html         # Base template
│   ├── accounts/         # Login, Register templates
│   ├── students/         # Dashboard templates
│   └── documents/        # Document templates
│
├── static/               # Static files
│   ├── css/              # Custom CSS
│   └── js/               # Custom JavaScript
│
├── media/                # Uploaded files (created after first upload)
│
├── mbbs_visa/            # Django project settings
│   ├── settings.py       # Project configuration
│   └── urls.py           # Main URL configuration
│
└── manage.py             # Django management script
```

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone or Navigate to Project Directory

```bash
cd d:\mbbs
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Run Migrations

```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate
```

### Step 5: Create Superuser (Admin Account)

```bash
python manage.py createsuperuser
```

Follow the prompts to create an admin account. **Important**: After creating the superuser, you need to set the role to 'ADMIN':

1. Run Django shell:
```bash
python manage.py shell
```

2. Execute the following commands:
```python
from accounts.models import User
admin_user = User.objects.get(username='your_admin_username')
admin_user.role = 'ADMIN'
admin_user.save()
exit()
```

Alternatively, you can use Django admin panel:
1. Start the server: `python manage.py runserver`
2. Go to http://127.0.0.1:8000/admin/
3. Login with your superuser credentials
4. Navigate to Users, find your user, and change the role to 'ADMIN'

### Step 6: Create Media Directory

```bash
# Windows
mkdir media

# Linux/Mac
mkdir media
```

### Step 7: Run Development Server

```bash
python manage.py runserver
```

The application will be available at: **http://127.0.0.1:8000/**

## Usage Guide

### For Students

1. **Registration**
   - Go to http://127.0.0.1:8000/register/
   - Fill in all required information
   - Click "Register"
   - Login with your credentials

2. **Complete Profile**
   - After login, go to "Profile" in the navigation
   - Enter your Passport Number and Address
   - Save the profile

3. **Upload Documents**
   - Click "Upload Document" in the navigation
   - Select document type
   - Choose file (PDF, JPG, JPEG, PNG - Max 10MB)
   - Optionally add a title
   - Click "Upload Document"

4. **View Status**
   - Check your dashboard for current visa status
   - View all uploaded documents
   - Download documents as needed

### For Admins

1. **Login**
   - Go to http://127.0.0.1:8000/login/
   - Use your admin credentials
   - You'll be redirected to Admin Dashboard

2. **View Students**
   - Dashboard shows all registered students
   - View analytics (Total, Approved, Pending, Rejected)
   - Click "View Details" on any student

3. **Manage Student**
   - View complete student profile
   - See all uploaded documents
   - Upload additional documents for the student
   - Update visa status

4. **Update Visa Status**
   - Go to student detail page
   - Select new status from dropdown
   - Click "Update Status"

## Database Models

### User Model (Custom)
- Extends Django's AbstractUser
- Fields: username, email, password, first_name, last_name, phone_number, role
- Roles: STUDENT, ADMIN

### StudentProfile Model
- One-to-One relationship with User
- Fields: passport_number, address, visa_status, created_at, updated_at
- Status choices: REGISTERED, DOCUMENTS_SUBMITTED, UNDER_REVIEW, APPROVED, REJECTED

### Document Model
- Foreign Key to User (student)
- Fields: document_type, file, title, uploaded_by, uploaded_at
- Document types: 10TH_MARKSHEET, 12TH_MARKSHEET, AADHAAR, PAN, ADDITIONAL

## Security Features

- ✅ Password hashing (Django's default PBKDF2)
- ✅ CSRF protection
- ✅ Secure file uploads with validation
- ✅ Role-based access control
- ✅ User authentication required for all views
- ✅ Admin-only views protected with decorators
- ✅ File size limits (10MB)

## File Upload Configuration

- **Upload Location**: `media/documents/{username}/{document_type}/{filename}`
- **Max File Size**: 10MB
- **Allowed Formats**: PDF, JPG, JPEG, PNG
- **Storage**: Local filesystem (can be changed to cloud storage in production)

## Production Deployment Considerations

1. **Change SECRET_KEY** in `settings.py`
2. **Set DEBUG = False**
3. **Configure ALLOWED_HOSTS**
4. **Use PostgreSQL or MySQL** instead of SQLite
5. **Set up proper media file serving** (e.g., AWS S3, Azure Blob)
6. **Enable HTTPS**
7. **Set up proper logging**
8. **Configure static files** (use `collectstatic`)
9. **Set up backup strategy**
10. **Use environment variables** for sensitive data

## Troubleshooting

### Issue: "No module named 'django'"
**Solution**: Activate virtual environment and install requirements:
```bash
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### Issue: "Migration errors"
**Solution**: Delete `db.sqlite3` and migration files in app folders (except `__init__.py`), then:
```bash
python manage.py makemigrations
python manage.py migrate
```

### Issue: "Media files not loading"
**Solution**: Ensure `media` directory exists and check `MEDIA_ROOT` and `MEDIA_URL` in settings.py

### Issue: "Admin cannot access admin dashboard"
**Solution**: Ensure user role is set to 'ADMIN' in database

## Testing

To test the application:

1. Create a student account via registration
2. Login as student and complete profile
3. Upload documents
4. Login as admin
5. View student details
6. Upload document for student
7. Update visa status
8. Check student dashboard to see admin-uploaded document

## Support

For issues or questions, please refer to the Django documentation:
- https://docs.djangoproject.com/

## License

This project is developed for FIFO University (Russia) MBBS Visa Management System.

---

**Developed with ❤️ using Django**
