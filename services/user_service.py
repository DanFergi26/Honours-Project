# -- User_Serivce.py
# -- Imports
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

# TEMP STORAGE
temp_signup_users = {}
temp_login_codes = {}
temp_password_resets = {}

# HELPER
def generate_code(length=6):
    return "".join(random.choices(string.digits, k=length))


def safe_string(value, max_length=255):
    if not value:
        return None
    value = str(value).strip()
    return value[:max_length]


def get_location_from_ip(ip):
    try:
        if not ip:
            return "Unknown location"

        ip = ip.split(",")[0].strip()

        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city"
        resp = requests.get(url, timeout=3)
        data = resp.json()

        if data.get("status") != "success":
            return "Unknown location"

        city = data.get("city")
        region = data.get("regionName")
        country = data.get("country")

        parts = [p for p in [city, region, country] if p]
        return ", ".join(parts) if parts else "Unknown location"

    except Exception:
        return "Unknown location"


# SIGNUP
def register_user(form_data, files):
    username = safe_string(form_data.get("username"), 50)
    email = safe_string(form_data.get("email"), 255)
    password = form_data.get("password")
    re_password = form_data.get("repassword")

    if not username or not email or not password or not re_password:
        return None, "All fields are required."

    # PASSWORD REQUIREMENTS
    if len(password) < 8:
        return None, "Password must be at least 8 characters."

    if password != re_password:
        return None, "Passwords do not match."

    # USERNAME OR EMAIL ALREADY EXISTS
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

    # TEMPORARILY SIGN UP USER
    temp_signup_users[email] = {
        "form_data": form_data,
        "code": code,
        "profile_pic": profile_pic
    }

    # SEND VERIFICATION CODE
    send_verification_email(email, code, subject="Signup Verification Code")

    return {"username": username, "email": email}, None


# VERIFY SIGNUP
def verify_signup_code(email, code):
    data = temp_signup_users.get(email)
    # NO SIGNUP REQUESTS
    if not data:
        return None, "No signup request found."

    # WRONG CODE
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
        # SIGNUP USER
        db.session.add(user)
        db.session.commit()

        del temp_signup_users[email]
        return user, None

    # ERROR
    except Exception:
        db.session.rollback()
        return None, "Error creating user account."


# LOGIN 
def authenticate_user(username, password):
    username = safe_string(username, 50)
    user = User.query.filter_by(username=username).first()

    # USER NOT FOUND
    if not user:
        return None, "User not found."

    # WRONG PASSWORD
    if not check_password_hash(user.password, password):
        return None, "Incorrect password."

    code = generate_code()
    temp_login_codes[username] = code

    # SEND VERIFICATION CODE
    send_verification_email(user.email, code, subject="Login Verification Code")

    return user, "code sent"


# VERIFY LOGIN 
def verify_login_code(username, code):
    expected = temp_login_codes.get(username)

    # NO LOGIN ATTEMPT
    if not expected:
        return None, "No login attempt found."

    # WRONG CODE
    if expected != code:
        return None, "Invalid verification code."

    del temp_login_codes[username]

    # LOGIN USER
    user = User.query.filter_by(username=username).first()

    return user, "Login successful"


# LOGGING
def log_login_attempt(user, username, success, ip=None, timed_out=False, send_alert=True):

    # GET IP
    ip = ip or "0.0.0.0"

    log = LoginLog(
        user_id=user.id if user else None,
        username_attempted=username,
        ip_address=ip,
        success=success,
        timed_out=timed_out
    )
    
    # STORE LOGIN ATTEMPT
    db.session.add(log)
    db.session.commit()

    # IF SUCCESFUL SEND LOGIN ALERT
    if success and user and send_alert:
        location = get_location_from_ip(ip)
        change_password_url = url_for("change_password", _external=True)
        send_login_alert_email(user.email, location, change_password_url)


# PASSWORD RESET
def create_password_reset(email):
    user = User.query.filter_by(email=email).first()

    # EMAIL IS INCORRECT
    if not user:
        return None, "No account found with that email."

    code = generate_code()
    temp_password_resets[email] = code

    # SEND VERIFICATION CODE
    send_verification_email(email, code, subject="Password Reset Code")

    return True, None


def verify_password_reset_code(email, code):
    expected_code = temp_password_resets.get(email)

    # NO REQUEST MADE
    if not expected_code:
        return None, "No reset request found."

    # WRONG CODE
    if expected_code != code:
        return None, "Invalid code."

    return True, None


def change_user_password(email, new_password, confirm_password):
    # SESSION EXPIRED
    if not email:
        return None, "Session expired. Please restart reset process."

    if not new_password or not confirm_password:
        return None, "All fields are required."
    
    # MISMATCHING PASSWORDS
    if new_password != confirm_password:
        return None, "Passwords do not match."

    # PASSWORD REQUIREMENTS
    if len(new_password) < 8:
        return None, "Password must be at least 8 characters."

    user = User.query.filter_by(email=email).first()

    # WRONG USER
    if not user:
        return None, "User not found."

    # OLD AND NEW PASSWORD ARE TEH SAME
    if check_password_hash(user.password, new_password):
        return None, "New password cannot be the same as the old password."
    
    # UPDATE PASSWORD
    user.password = generate_password_hash(new_password).decode("utf-8")
    db.session.commit()

    return True, "updated successfully"


# USERS 
def get_current_user():
    if not session.get("logged_in"):
        return None
    return User.query.filter_by(username=session.get("username")).first()


def get_all_users_with_permissions(current_user):
    users = User.query.all()

    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "roleID": u.roleID,
            "profile_pic": u.profile_pic,
            "forename": u.forename,
            "surname": u.surname,
            "country": u.country,
            "dob": u.dob,
            "bio": u.bio
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