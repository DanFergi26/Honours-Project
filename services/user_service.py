from models.models import db, User, fernet, LoginLog
from flask_bcrypt import generate_password_hash, check_password_hash
from flask import request, url_for
from services.email_service import send_verification_email, send_login_alert_email
import random
import string
import requests

# ---------------- Temp storage for 2FA ----------------
temp_signup_users = {}   # key: email, value: {form_data, code}
temp_login_codes = {}    # key: username, value: code

# ---------------- Helpers ----------------
def generate_code(length=6):
    return "".join(random.choices(string.digits, k=length))

def encrypt_value(value):
    if not value:
        return None
    return fernet.encrypt(value.encode())

def get_location_from_ip(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}")
        data = resp.json()
        city = data.get("city")
        region = data.get("regionName")
        country = data.get("country")
        if city and region and country:
            return f"{city}, {region}, {country}"
        elif country:
            return country
        else:
            return "an unknown location"
    except Exception:
        return "an unknown location"

# ---------------- Signup ----------------
def register_user(form_data):
    # ... same as before ...
    code = generate_code()
    temp_signup_users[email] = {"form_data": form_data, "code": code}

    # Send email via email_service
    send_verification_email(email, code, subject="Signup Verification Code")

    return {"username": username, "email": email}, None

def verify_signup_code(email, code):
    # ... same as before ...
    return user, None

# ---------------- Login ----------------
def authenticate_user(username, password):
    # ... same as before ...
    code = generate_code()
    temp_login_codes[username] = code

    # Send verification email via email_service
    send_verification_email(user.email, code, subject="Login Verification Code")

    return user, None

def verify_login_code(username, code):
    # ... same as before ...
    return None

# ---------------- Login Logging ----------------
def log_login_attempt(user, username, success, ip=None, timed_out=False, send_alert=True):
    """
    Logs the login attempt to DB, and optionally sends a login alert email
    for successful logins.
    """
    if ip is None:
        ip = "0.0.0.0"  # fallback, Flask request should provide IP

    log = LoginLog(
        user_id=user.id if user else None,
        username_attempted=username,
        ip_address=ip,
        success=success,
        timed_out=timed_out
    )
    db.session.add(log)
    db.session.commit()

    # If login succeeded, send alert email
    if success and user and send_alert:
        location = get_location_from_ip(ip)
        change_password_url = url_for("change_password", _external=True)
        send_login_alert_email(user.email, location, change_password_url)

# ---------------- Users list ----------------
def get_all_users_with_permissions(current_user):
    # ... same as before ...
    return users_list