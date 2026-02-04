# Testing Guide

## Running tests

From the project root (`mbbs/`):

```bash
python manage.py test
```

Run specific apps:

```bash
python manage.py test accounts.tests
python manage.py test students.tests
python manage.py test documents.tests
```

Reuse the test database (faster for repeated runs):

```bash
python manage.py test --keepdb
```

## What is covered

- **accounts**: User model (roles, `is_admin`/`is_student`), superuser role=ADMIN, landing/login/register/logout views and redirects.
- **students**: Dashboard (student vs admin), admin dashboard access, student detail, admin edit student (form + confirm), admin delete student (confirm), profile edit, URL reversal for all named routes.
- **documents**: Upload/delete permissions, admin document delete creating a re-upload notification, download permission, URL reversal.

## Test settings

When running tests, the project automatically uses `StaticFilesStorage` (no manifest) so `collectstatic` is not required. Production continues to use Whitenoise’s `CompressedManifestStaticFilesStorage`.

## Deployment checklist

Before deployment, run:

1. `python manage.py check`
2. `python manage.py test`

Ensure no tests are skipped or failing so the app does not crash on common operations.
