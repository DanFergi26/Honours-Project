from models.models import db, User, RolePermissions, LoginLog
import os
import uuid
from config import PROFILE_PICS_FOLDER
from werkzeug.utils import secure_filename
from flask_bcrypt import generate_password_hash, check_password_hash
from flask import url_for, session
from services.email_service import send_verification_email, send_login_alert_email
import random
import string
import requests

# ---------------- Temp storage ----------------
temp_signup_users = {}
temp_login_codes = {}
temp_password_resets = {}

# ---------------- Helpers ----------------
def generate_code(length=6):
    return "".join(random.choices(string.digits, k=length))


def safe_string(value, max_length=255):
    """
    Basic input sanitisation (prevents abuse, not SQL injection)
    """
    if not value:
        return None
    value = str(value).strip()
    return value[:max_length]


def get_location_from_ip(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = resp.json()
        city = data.get("city")
        region = data.get("regionName")
        country = data.get("country")

        if city and region and country:
            return f"{city}, {region}, {country}"
        elif country:
            return country
        return "an unknown location"
    except Exception:
        return "an unknown location"


# ---------------- Signup ----------------
def register_user(form_data, files):

    username = safe_string(form_data.get("username"), 50)
    email = safe_string(form_data.get("email"), 255)
    password = form_data.get("password")
    re_password = form_data.get("repassword")

    if not username or not email or not password or not re_password:
        return None, "All fields are required."

    if len(password) < 8:
        return None, "Password must be at least 8 characters."

    if password != re_password:
        return None, "Passwords do not match."

    if User.query.filter_by(username=username).first():
        return None, "Username already exists."

    if User.query.filter_by(email=email).first():
        return None, "Email already exists."

    profile_pic = None

    file = files.get("propic")

    if file and file.filename:
        filename = secure_filename(file.filename)
        filename = f"{uuid.uuid4().hex}_{filename}"
        file.save(os.path.join(PROFILE_PICS_FOLDER, filename))

        profile_pic = filename

    code = generate_code()

    temp_signup_users[email] = {
        "form_data": form_data,
        "code": code,
        "profile_pic": profile_pic   # FIX: store file result
    }

    send_verification_email(email, code, subject="Signup Verification Code")

    return {"username": username, "email": email}, None


# ---------------- Verify Signup ----------------
def verify_signup_code(email, code):

    data = temp_signup_users.get(email)
    if not data:
        return None, "No signup request found."

    if data["code"] != code:
        return None, "Invalid verification code."

    form_data = data["form_data"]

    try:
        hashed_password = generate_password_hash(form_data["password"]).decode("utf-8")

        user = User(
            username=safe_string(form_data.get("username"), 50),
            surname=form_data.get("surname"),
            forename=form_data.get("forename"),
            email=form_data.get("email"),
            dob=form_data.get("dob"),
            country=form_data.get("country"),
            bio=form_data.get("bio", ""),
            password=hashed_password,
            profile_pic=data.get("profile_pic")
        )

        db.session.add(user)
        db.session.commit()

        del temp_signup_users[email]
        return user, None

    except Exception:
        db.session.rollback()
        return None, "Error creating user account."


# ---------------- Login ----------------
def authenticate_user(username, password):

    username = safe_string(username, 50)

    user = User.query.filter_by(username=username).first()

    if not user:
        return None, "User not found."

    if not check_password_hash(user.password, password):
        return None, "Incorrect password."

    code = generate_code()
    temp_login_codes[username] = code

    send_verification_email(user.email, code, subject="Login Verification Code")

    return user, None


# ---------------- Verify Login ----------------
def verify_login_code(username, code):

    expected = temp_login_codes.get(username)

    if not expected:
        return None, "No login attempt found."

    if expected != code:
        return None, "Invalid verification code."

    del temp_login_codes[username]

    user = User.query.filter_by(username=username).first()
    return user, None


# ---------------- Logging ----------------
def log_login_attempt(user, username, success, ip=None, timed_out=False, send_alert=True):

    ip = ip or "0.0.0.0"

    log = LoginLog(
        user_id=user.id if user else None,
        username_attempted=username,
        ip_address=ip,
        success=success,
        timed_out=timed_out
    )

    db.session.add(log)
    db.session.commit()

    if success and user and send_alert:
        location = get_location_from_ip(ip)
        change_password_url = url_for("change_password", _external=True)
        send_login_alert_email(user.email, location, change_password_url)

# ---------------- Change Password ----------------

def create_password_reset(email):
    users = User.query.all()
    user = next((u for u in users if u.email == email), None)

    if not user:
        return None, "No account found with that email."

    code = generate_code()

    temp_password_resets[email] = code

    send_verification_email(
        email,
        code,
        subject="Password Reset Code"
    )

    return True, None
    
def verify_password_reset_code(email, code):
    expected_code = temp_password_resets.get(email)

    if not expected_code:
        return None, "No reset request found."

    if expected_code != code:
        return None, "Invalid code."

    return True, None

def change_user_password(email, new_password, confirm_password):
    if not email:
        return None, "Session expired. Please restart reset process."

    if not new_password or not confirm_password:
        return None, "All fields are required."

    if new_password != confirm_password:
        return None, "Passwords do not match."

    if len(new_password) < 8:
        return None, "Password must be at least 8 characters."

    user = User.query.filter_by(email=email).first()

    if not user:
        return None, "User not found."

    # prevent reusing old password
    if check_password_hash(user.password, new_password):
        return None, "New password cannot be the same as the old password."

    # set new password
    user.password = generate_password_hash(new_password).decode("utf-8")

    db.session.commit()

    return True, None
    
# ---------------- Users ----------------

def get_current_user():
    if not session.get("logged_in"):
        return None
    return User.query.filter_by(username=session.get("username")).first()
    
def get_all_users_with_permissions(current_user):

    users = User.query.all()

    return [
        {
            "username": u.username,
            "email": u.email,
            "roleID": u.roleID
        }
        for u in users
    ]
    
def user_has_permission(user, perm_id):
    if not user or not user.roleID:
        return False

    return RolePermissions.query.filter_by(
        roleID=user.roleID,
        permissionsID=perm_id
    ).first() is not None