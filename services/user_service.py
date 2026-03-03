# services/user_service.py
from models.models import db, User, fernet
from flask_bcrypt import generate_password_hash, check_password_hash
from services.email_service import send_verification_email
import random
import string

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

# ---------------- Signup ----------------
def register_user(form_data):
    email = form_data.get("email")
    username = form_data.get("username")
    password = form_data.get("password")
    repassword = form_data.get("repassword")

    # Basic validation
    if not email or not username or not password:
        return None, "All fields are required."
    if password != repassword:
        return None, "Passwords must match."
    if len(password) < 8:
        return None, "Password must be at least 8 characters."
    if User.query.filter_by(username=username).first():
        return None, "Username already exists."

    # Check email uniqueness (encrypt first)
    encrypted_email = encrypt_value(email)
    if User.query.filter_by(_email=encrypted_email).first():
        return None, "Email already registered."

    # Generate verification code and store in temp
    code = generate_code()
    temp_signup_users[email] = {"form_data": form_data, "code": code}

    # Send email with code
    send_verification_email(email, code, subject="Signup Verification Code")

    return {"username": username, "email": email}, None


def verify_signup_code(email, code):
    entry = temp_signup_users.get(email)
    if not entry:
        return None, "No signup attempt found for this email."
    if entry["code"] != code:
        return None, "Incorrect verification code."

    # Create the user
    data = entry["form_data"]
    user = User(
        username=data["username"],
        surname=data.get("surname", ""),
        forename=data.get("forename", ""),
        email=data["email"],
        dob=data.get("dob", ""),
        country=data.get("country", "")
    )
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()

    # Remove from temp storage
    del temp_signup_users[email]

    return user, None
# ---------------- Login ----------------
def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if not user:
        return None, "Account does not exist."
    if not user.check_password(password):
        return None, "Password incorrect."

    # Generate login code
    code = generate_code()
    temp_login_codes[username] = code
    send_verification_email(user.email, code, subject="Login Verification Code")

    return user, None


def verify_login_code(username, code):
    expected_code = temp_login_codes.get(username)
    if not expected_code:
        return "No login attempt found for this user."
    if expected_code != code:
        return "Incorrect verification code."

    del temp_login_codes[username]
    return None

# ---------------- Users list ----------------
def get_all_users_with_permissions(current_user):
    users_list = []
    for u in User.query.all():
        users_list.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "surname": u.surname,
            "forename": u.forename,
            "roleID": u.roleID
        })
    return users_list