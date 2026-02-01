# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Setup Database
```bash
python manage.py makemigrations
python manage.py migrate
```

### 3. Create Admin User
```bash
python manage.py shell
```

Then paste this:
```python
from accounts.models import User
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
print("✅ Admin created! Username: admin, Password: admin123")
exit()
```

### 4. Create Media Folder
```bash
mkdir media
```

### 5. Run Server
```bash
python manage.py runserver
```

### 6. Access Application
- **Login**: http://127.0.0.1:8000/login/
- **Register**: http://127.0.0.1:8000/register/
- **Admin Dashboard**: http://127.0.0.1:8000/students/admin/dashboard/

## 🎯 Test the Application

### As Student:
1. Register at `/register/`
2. Login
3. Complete profile (add passport & address)
4. Upload documents
5. Check visa status

### As Admin:
1. Login with admin credentials
2. View all students
3. Click on a student
4. Upload document for student
5. Update visa status

## 📝 Default Credentials (Change in Production!)

**Admin:**
- Username: `admin`
- Password: `admin123`

**⚠️ IMPORTANT**: Change these credentials before deploying to production!

## 🔧 Common Commands

```bash
# Create superuser (alternative method)
python manage.py createsuperuser

# Collect static files (for production)
python manage.py collectstatic

# Create new migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Run development server
python manage.py runserver

# Run on specific port
python manage.py runserver 8001
```

## 📚 Documentation

- **Full Documentation**: See `README.md`
- **Setup Instructions**: See `SETUP_INSTRUCTIONS.md`
- **Project Summary**: See `PROJECT_SUMMARY.md`

## 🆘 Need Help?

1. Check `SETUP_INSTRUCTIONS.md` for detailed setup
2. Check `README.md` for complete documentation
3. Review Django documentation: https://docs.djangoproject.com/

---

**Ready to go!** 🎉
