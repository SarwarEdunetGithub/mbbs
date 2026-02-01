# 🎉 MBBS Visa Management System - Application Running!

## ✅ Server Status: RUNNING

The Django development server is successfully running on your machine.

## 🌐 Access URLs

### Main Application
- **Home/Login**: http://127.0.0.1:8000/
- **Student Registration**: http://127.0.0.1:8000/register/
- **Login Page**: http://127.0.0.1:8000/login/

### Student Portal (After Login)
- **Student Dashboard**: http://127.0.0.1:8000/students/dashboard/
- **Edit Profile**: http://127.0.0.1:8000/students/profile/edit/
- **Upload Documents**: http://127.0.0.1:8000/documents/upload/

### Admin Portal (After Admin Login)
- **Admin Dashboard**: http://127.0.0.1:8000/students/admin/dashboard/
- **Django Admin Panel**: http://127.0.0.1:8000/admin/

## 🔑 Login Credentials

### Admin Account
- **Username**: `admin`
- **Password**: `admin123`
- **Role**: Admin

### Test Student Account
You can create a student account by:
1. Going to http://127.0.0.1:8000/register/
2. Filling in the registration form
3. Logging in with your credentials

## 📋 Quick Test Guide

### Test as Student:
1. Open browser: http://127.0.0.1:8000/register/
2. Register a new student account
3. Login with your credentials
4. Complete your profile (add passport number and address)
5. Upload documents (10th, 12th, Aadhaar, PAN)
6. Check your visa status on dashboard

### Test as Admin:
1. Open browser: http://127.0.0.1:8000/login/
2. Login with admin credentials (admin/admin123)
3. View all registered students
4. Click on any student to view details
5. Upload documents for students
6. Update visa status
7. View analytics

## 🛠️ Server Management

### Stop the Server
Press `Ctrl + C` in the terminal where the server is running

### Restart the Server
```bash
python manage.py runserver
```

### Run on Different Port
```bash
python manage.py runserver 8001
```

## 📊 Application Features

### ✅ Implemented Features:
- Student registration and authentication
- Admin authentication (no public registration)
- Student dashboard with profile management
- Document upload system (PDF, JPG, PNG)
- Admin dashboard with analytics
- Student management for admins
- Visa status tracking
- Document management (upload, view, download, delete)
- Role-based access control
- Responsive UI with Bootstrap 5

### 📈 Visa Status Workflow:
1. **REGISTERED** - Initial status after registration
2. **DOCUMENTS_SUBMITTED** - After first document upload
3. **UNDER_REVIEW** - Admin sets when reviewing
4. **APPROVED** - Visa approved
5. **REJECTED** - Visa rejected

## 🔒 Security Features

- Password hashing (Django's PBKDF2)
- CSRF protection
- Role-based access control
- Secure file uploads
- File size validation (10MB limit)
- Authentication required for all views

## 📁 File Upload Guidelines

### Accepted Document Types:
- 10th Marksheet
- 12th Marksheet
- Aadhaar Card
- PAN Card
- Additional Documents

### File Requirements:
- **Formats**: PDF, JPG, JPEG, PNG
- **Max Size**: 10MB per file
- **Storage**: Files are stored in `media/documents/{username}/{document_type}/`

## 🆘 Troubleshooting

### Issue: Cannot access the application
**Solution**: Make sure the server is running. Check terminal for errors.

### Issue: "Page not found" error
**Solution**: Make sure you're using the correct URL (http://127.0.0.1:8000/)

### Issue: Cannot login
**Solution**: 
- For admin: Use username `admin` and password `admin123`
- For student: Make sure you've registered first

### Issue: Cannot upload files
**Solution**: 
- Check file size (must be under 10MB)
- Check file format (PDF, JPG, JPEG, PNG only)
- Make sure `media` directory exists

## 📞 Support

For detailed documentation, see:
- **README.md** - Complete project documentation
- **SETUP_INSTRUCTIONS.md** - Setup guide
- **PROJECT_SUMMARY.md** - Architecture overview
- **QUICK_START.md** - Quick reference

## ⚠️ Important Notes

1. **Change Admin Password**: Before deploying to production, change the default admin password!
2. **Debug Mode**: Currently running in DEBUG mode. Set `DEBUG=False` for production.
3. **Secret Key**: Change the SECRET_KEY in settings.py for production.
4. **Database**: Currently using SQLite. Consider PostgreSQL/MySQL for production.

---

**Status**: ✅ Application is running successfully!

**Server**: http://127.0.0.1:8000/

**Last Started**: 2026-02-01

Enjoy using the MBBS Visa Management System! 🎓
