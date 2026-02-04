# Change Password – Implementation Notes

## Overview

The change-password feature is implemented with Django only (no extra frameworks). It lives under **accounts** (form + view) and is exposed at **/students/settings/password/** (login required).

## Wiring to Django Auth

- **Form:** `accounts.forms.ChangePasswordForm`  
  - Takes `user` in `__init__` to verify current password.  
  - Uses `django.contrib.auth.password_validation.validate_password()` for the new password, so **AUTH_PASSWORD_VALIDATORS** in `settings.py` are enforced (minimum length, common passwords, numeric-only, etc.).

- **View:** `accounts.views.change_password_view`  
  - Decorator: `@login_required(login_url='accounts:login')`.  
  - On success: `user.set_password(new_password)`, `user.save()`, then:  
    - `update_session_auth_hash(request, user)` so the session stays valid with the new password.  
    - `request.session.cycle_key()` so the current session gets a new key (good practice after sensitive actions).

- **URL:** In `students.urls`:  
  `path('settings/password/', change_password_view, name='settings_password')`  
  Full URL: **/students/settings/password/**.

- **Template:** `accounts/change_password.html` extends `accounts/accountbase.html`, uses existing `theme.css` and `app.js` (password toggles, optional `data-validate`).

## Security

- **CSRF:** Enforced by Django middleware on POST.
- **Current password:** Checked in `ChangePasswordForm.clean_current_password()` via `user.check_password(current_password)`.
- **New password:** Validated with `validate_password()` (all `AUTH_PASSWORD_VALIDATORS`).
- **Session:** Re-authenticated with `update_session_auth_hash`; session key rotated with `cycle_key()`.
- **Rate limiting:** After **5** failed attempts (wrong current password or validation errors), further attempts are blocked for **15 minutes** using Django’s default cache (`cache.get/set`). Key: `pwd_change_fail:{user.pk}`. For multi-worker/production, use a shared cache (e.g. Redis) so the limit is global.
- **Logging:** On success, `logger.info('Password changed for user_id=%s', user.pk)`. Ensure `LOGGING` in settings configures this logger if you want it in files or monitoring.

## Edge Cases

- **Incorrect current password:** Form error: “The current password is incorrect.” Rate-limit counter incremented.
- **Weak new password:** `validate_password()` raises; error message comes from the validator (e.g. “This password is too common.”).
- **New password mismatch:** Form error: “The two new password fields did not match.”
- **Rate limited:** User is redirected to the same page and sees: “Too many failed attempts. Please try again in about 15 minutes.” Form is not rendered; counter resets after 15 minutes.

## Post-Success Behaviour

- User remains logged in on the **current** device (same browser/session).
- **Other devices:** `cycle_key()` only rotates the current session key. It does **not** log out other devices. To “sign the user out of other devices” you need one of:
  - **Option A:** Store a “session version” or “password_changed_at” on the user (or user profile). In custom middleware, compare with a value stored in the session; if the session is older than the password change, clear the session and redirect to login.
  - **Option B:** If using database sessions, iterate `Session.objects.all()`, decode `session_data`, and delete sessions where the user id matches and `session_key != request.session.session_key` (expensive and only practical with a small number of sessions or background task).

A **configurable** approach is to add a setting, e.g.:

```python
# settings.py
PASSWORD_CHANGE_INVALIDATE_OTHER_SESSIONS = False  # Set True to enable Option A via middleware
```

Then implement middleware that checks a “password_changed_at” (or similar) field on the user and invalidates sessions that were created before that time.

## Optional: Require Re-Login After Change

If policy demands re-login after a password change (even on the same device):

1. Do **not** call `update_session_auth_hash()` after `set_password()`.
2. Call `logout(request)` (or clear the session) and redirect to login with a message like “Password updated. Please log in again.”

Current implementation keeps the user logged in on the current device and does not require re-login unless you change it as above.

## Files Touched

| File | Role |
|------|------|
| `accounts/forms.py` | `ChangePasswordForm` |
| `accounts/views.py` | `change_password_view`, rate limit, logging |
| `students/urls.py` | `path('settings/password/', ...)` |
| `templates/accounts/accountbase.html` | Nav: when authenticated, show Dashboard / Password / Logout |
| `templates/accounts/change_password.html` | Form UI, aria-live, policy text, toggles |
| `templates/base.html` | Nav: “Password” link for dashboard users |

No new CSS/JS files: `theme.css` (form-card, password-toggle-wrapper) and `app.js` (password toggles, optional validation) are reused.
