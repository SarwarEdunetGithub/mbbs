# Forgot Password – Configuration Notes

## URLs

| URL | Name | Description |
|-----|------|-------------|
| `/auth/forgot-password/` | `auth:forgot_password` | Request form (email and/or phone). Always returns generic success. |
| `/auth/login/` | `auth:login` | Login; if user has valid temp password, redirects to force-change and invalidates temp. |
| `/auth/force-change-password/` | `auth:force_change_password` | Mandatory new password after temp login (requires `must_change_password` session). |

Existing `/login/` and `/forgot-password/` (accounts app) still work; the canonical flow uses `/auth/` for consistency.

## Settings (environment or `settings.py`)

| Setting | Default | Description |
|---------|---------|-------------|
| `PASSWORD_RESET_TEMP_VALID_MINUTES` | 15 | How long the one-time password is valid. |
| `PASSWORD_RESET_MAX_PER_USER_PER_DAY` | 2 | Max reset requests per student per calendar day. |
| `PASSWORD_RESET_MAX_PER_IP_PER_HOUR` | 10 | Max requests per IP per hour (soft throttle). |
| `SEND_EMAIL_ENABLED` | True | Whether to attempt email delivery. |
| `SEND_SMS_ENABLED` | False | Whether to attempt SMS delivery. |

Use `python-decouple` in production, e.g. in `.env`:

```
PASSWORD_RESET_TEMP_VALID_MINUTES=15
PASSWORD_RESET_MAX_PER_USER_PER_DAY=2
PASSWORD_RESET_MAX_PER_IP_PER_HOUR=10
SEND_EMAIL_ENABLED=true
SEND_SMS_ENABLED=false
```

## SMS/Email adapters

- **Module:** `accounts/notifications.py`
- **Functions:** `send_email(to, subject, body)` and `send_sms(to, message)`.
- **Behaviour:** Return `True` on success, `False` on failure. When disabled via settings, they return `False` (email) or log and return `False` (SMS) without sending.
- **Email:** Uses Django’s `send_mail()`; set `DEFAULT_FROM_EMAIL` and configure `EMAIL_*` in settings for real delivery.
- **SMS:** Stub only; replace with Twilio, AWS SNS, etc., and keep the same function signature.

## Security

- **CSRF:** Enforced by Django middleware on all POSTs.
- **Passwords:** Only hashed values are stored; temporary passwords are never logged.
- **Audit:** Every request is recorded in `PasswordResetAuditLog` (user, IP, user_agent, channels attempted/success, result). No plaintext passwords.
- **Non-enumeration:** Same generic success message and similar response time whether the account exists or not.
- **Rate limits:** Per-user (calendar day) and per-IP (hour) enforced before sending; cache keys: `pwd_reset_ip:{ip}` (TTL 3600s).

## Flow

1. User submits email and/or phone on `/auth/forgot-password/`.
2. If a **student** matches (by email or phone): check per-user and per-IP limits → generate strong temp password → invalidate any previous temp → set `user.set_password(temp)`, `user.temp_password_expires_at = now + valid_minutes` → send email and/or SMS (both attempted if enabled) → audit with channel status.
3. If no match or rate limited: still audit; same generic success message and delay.
4. User logs in at `/auth/login/` with username + temp password.
5. If `temp_password_expires_at` is in the past: login rejected with “expired” message.
6. If valid: login succeeds → temp is invalidated (password set to random, `temp_password_expires_at` cleared) → `session['must_change_password'] = True` → redirect to `/auth/force-change-password/`.
7. User sets new password → session flag cleared → redirect to dashboard.

## Models

- **User:** `temp_password_expires_at` (DateTimeField, null=True). When set, indicates a temporary password valid until that time.
- **PasswordResetAuditLog:** `user` (FK, null if no match), `requested_at`, `email_attempted`, `email_success`, `sms_attempted`, `sms_success`, `ip_address`, `user_agent`, `result` (sent / rate_limit_user / rate_limit_ip / no_match).

## Tests

Run:

```bash
python manage.py test accounts.tests.test_forgot_password
```

Covered: GET 200, non-existing user (generic success), happy path (audit + send), 3rd attempt same day (per-user limit), expired temp (rejected at login), SMS/email failure (audit + generic success), one-time use (redirect to force-change, temp invalidated), force-change (session cleared, new password set), form validation (email or phone required).
