# services/user_service.py

from models.models import db, User, Roles, RolePermissions

def register_user(form_data, profile_pic_filename=None):
    username = form_data.get("username")
    surname = form_data.get("surname")
    forename = form_data.get("forename")
    email = form_data.get("email")
    dob = form_data.get("dob")
    country = form_data.get("country")
    password = form_data.get("password")
    repassword = form_data.get("repassword")

    existing_user = User.query.filter_by(username=username).first()

    # Cannot directly query encrypted email
    existing_email = any(u.email == email for u in User.query.all())

    if existing_user:
        return "Username already exists."
    if existing_email:
        return "Email already exists."
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if password != repassword:
        return "Passwords must match."

    user = User(
        username=username,
        surname=surname,
        forename=forename,
        email=email,
        dob=dob,
        country=country,
        profile_pic=profile_pic_filename
    )

    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return None


def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()

    if not user:
        return None, "Account doesn't exist"

    if not user.check_password(password):
        return None, "Password incorrect"

    return user, None


def get_all_users_with_permissions(current_user):
    show_sensitive = False

    if current_user and current_user.roleID:
        role_perms = RolePermissions.query.filter_by(roleID=current_user.roleID).all()
        if any(rp.permissionsID == 1 for rp in role_perms):
            show_sensitive = True

    users_list = []

    for u in User.query.all():
        users_list.append({
            "id": u.id,
            "username": u.username,
            "bio": u.bio,
            "roleID": u.roleID,
            "profile_pic": u.profile_pic,
            "surname": u.surname if show_sensitive else "[Hidden]",
            "forename": u.forename if show_sensitive else "[Hidden]",
            "dob": u.dob if show_sensitive else "[Hidden]",
            "country": u.country if show_sensitive else "[Hidden]",
            "email": u.email if show_sensitive else "[Hidden]"
        })

    return users_list