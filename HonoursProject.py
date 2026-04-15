from flask import Flask, request, redirect, url_for, flash, session, render_template, send_from_directory
from models.models import db, User, Roles, Permissions, RolePermissions, Figures, FigureImages, UserCollection, SubCollection, SubCollectionItem, LoginLog
from services.user_service import get_current_user, register_user, authenticate_user, get_all_users_with_permissions, user_has_permission, verify_signup_code, verify_login_code, log_login_attempt, create_password_reset, verify_password_reset_code, change_user_password
from services.role_service import create_permission, create_role, assign_permission_to_role, assign_role_to_user
from services.figure_service import add_figure, add_brand, add_manufacturer, get_all_brands, get_all_manufacturers
from services.email_service import send_verification_email
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import random

UPLOAD_FOLDER = "static/figure_images"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    
# ------------------- Flask App -------------------
app = Flask(__name__)
app.secret_key = "your_secret_key"

# ------------------- Database Setup -------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# MySQL Configuration
DB_USER = "root"              # your MySQL username
DB_PASSWORD = "password"      # your MySQL password
DB_HOST = "localhost"
DB_NAME = "honours_db"       # create this in MySQL first

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:Thecaptain2004!@localhost:3306/honours_db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

# ------------------- Create Database Tables -------------------
with app.app_context():
    db.create_all()

# ------------------- Static Folders -------------------
PROFILE_PICS_FOLDER = os.path.join(BASE_DIR, "static", "profile_pics")
os.makedirs(PROFILE_PICS_FOLDER, exist_ok=True)

@app.route("/profile_pics/<filename>")
def profile_pics(filename):
    return send_from_directory(PROFILE_PICS_FOLDER, filename)

@app.route("/")
def index_redirect():
    return redirect(url_for("loading"))

# ------------------- Loading -------------------
@app.route("/loading")
def loading():
    return render_template("loading.html")
    
# ------------------- Home -------------------
@app.route("/home")
def home():
    return render_template(
        "home.html",
        logged_in=session.get("logged_in", False),
        username=session.get("username"),
        profile_pic=session.get("profile_pic", "default_pfp.png")
    )

# ------------------- Signup with 2FA -------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        form_data = request.form
        user_info, error = register_user(form_data)
        if error:
            flash(error)
            return render_template("signup.html")

        # Store info in session for verification page
        session["signup_username"] = user_info["username"]
        session["signup_email"] = user_info["email"]

        flash("Verification code sent to your email.")
        return redirect(url_for("verify_signup"))

    return render_template("signup.html")


@app.route("/verify_signup", methods=["GET", "POST"])
def verify_signup():
    if request.method == "POST":
        entered_code = request.form.get("code")
        email = session.get("signup_email")

        if not email:
            flash("No signup attempt found. Please signup again.")
            return redirect(url_for("signup"))

        user, error = verify_signup_code(email, entered_code)
        if error:
            flash(error)
            return render_template("signup_verify.html")

        session.pop("signup_email", None)
        flash("Signup complete! You can now login.")
        return redirect(url_for("home"))

    return render_template("signup_verify.html")

# ------------------- Login with 2FA -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if not user:
            log_login_attempt(None, username, False)
            return render_template("home.html", message="Account does not exist.")

        # CHECK LOCKOUT
        if user.lockout_until and datetime.utcnow() < user.lockout_until:
            log_login_attempt(user, username, False, timed_out=True)
            return render_template("home.html", message="Account locked. Try again later.")

        if not user.check_password(password):
            user.failed_attempts += 1

            # LOCK AFTER 3 FAILS
            if user.failed_attempts >= 3:
                user.lockout_until = datetime.utcnow() + timedelta(minutes=10)
                db.session.commit()
                log_login_attempt(user, username, False, timed_out=True)
                return render_template("home.html", message="Too many attempts. Locked for 10 minutes.")

            db.session.commit()
            log_login_attempt(user, username, False)
            return render_template("home.html", message="Password incorrect.")

        # PASSWORD CORRECT
        user.failed_attempts = 0
        user.lockout_until = None
        db.session.commit()

        log_login_attempt(user, username, True)

        # Continue with 2FA as before
        code = str(random.randint(100000, 999999))

        session["login_username"] = user.username
        session["login_email"] = user.email
        session["login_code"] = code
        session["login_attempts"] = 0

        send_verification_email(user.email, code, subject="Login Verification Code")

        flash("2FA code sent to your email.")
        return redirect(url_for("verify_login"))

    return render_template("home.html")

@app.route("/verify_login", methods=["GET", "POST"])
def verify_login():
    if request.method == "POST":
        entered_code = request.form.get("code")
        email = session.get("login_email")

        if not email:
            flash("No login attempt found. Please login again.")
            return redirect(url_for("login"))

        if entered_code == session.get("login_code"):
            username = session.pop("login_username", None)
            session.pop("login_email", None)
            session.pop("login_code", None)
            session.pop("login_attempts", None)

            user = User.query.filter_by(username=username).first()
            session["logged_in"] = True
            session["username"] = username
            session["profile_pic"] = user.profile_pic or "default_pfp.png"
            flash("Login successful!")
            return redirect(url_for("home"))
        else:
            session["login_attempts"] = session.get("login_attempts", 0) + 1
            if session["login_attempts"] > 5:
                flash("Too many attempts. Please try login again later.")
                return redirect(url_for("login"))
            flash("Invalid verification code.")

    return render_template("login_verify.html")
    
# ------------------- Logout -------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ------------------- Users -------------------
@app.route("/users")
def users():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    current_user = User.query.filter_by(username=session["username"]).first()
    users_list = get_all_users_with_permissions(current_user)
    return render_template("users.html", users=users_list)

# ------------------- Permissions & Roles -------------------
@app.route("/permcreate", methods=["GET", "POST"])
def permcreate():
    if request.method == "POST":
        error = create_permission(request.form["permName"], request.form["permDesc"])

        if error:
            flash(error, "error")
        else:
            flash("Permission created successfully.", "success")

    return render_template("permcreate.html")


@app.route("/rolecreate", methods=["GET", "POST"])
def rolecreate():
    if request.method == "POST":
        error = create_role(request.form["roleName"], request.form["roleDesc"])

        if error:
            flash(error, "error")
        else:
            flash("Role created successfully.", "success")

    return render_template("rolecreate.html")


@app.route("/roleassign", methods=["GET", "POST"])
def roleassign():
    roles = Roles.query.all()
    perms = Permissions.query.all()

    if request.method == "POST":
        error = assign_permission_to_role(
            request.form["roleName"],
            request.form["permName"]
        )
        message = error if error else "Permission assigned successfully."
        return render_template("roleassign.html", roles=roles, perms=perms, message=message)

    return render_template("roleassign.html", roles=roles, perms=perms)


@app.route("/assignuser", methods=["GET", "POST"])
def assignuser():
    if request.method == "POST":
        error = assign_role_to_user(
            request.form["username"],
            request.form["role_id"]
        )
        message = error if error else "Role assigned successfully."
    else:
        message = None

    roles = Roles.query.all()
    users = User.query.all()

    return render_template(
        "assignuser.html",
        roles=roles,
        users=users,
        message=message
    )

# ------------------- Add Figure -------------------
@app.route("/addfigure", methods=["GET", "POST"])
def addfigure():
    brands = get_all_brands()
    manufacturers = get_all_manufacturers()

    if request.method == "POST":
        error = add_figure(request.form)

        if error:
            flash(error)
            return render_template("addfigure.html", brand=brands, manufacturer=manufacturers)

        # get last created figure (simple approach)
        figure = Figures.query.order_by(Figures.id.desc()).first()

        files = request.files.getlist("images")

        valid_files = [f for f in files if f and allowed_file(f.filename)]

        if len(valid_files) < 1:
            flash("You must upload at least 1 image.")
            return render_template("addfigure.html", brand=brands, manufacturer=manufacturers)

        if len(valid_files) > 5:
            flash("You can only upload up to 5 images.")
            return render_template("addfigure.html", brand=brands, manufacturer=manufacturers)

        for file in valid_files:
            filename = secure_filename(file.filename)
            path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(path)

            img = FigureImages(
                figure_id=figure.id,
                image_path=filename
            )
            db.session.add(img)

        db.session.commit()

        flash("Figure added successfully.")
        return redirect(url_for("addfigure"))

    return render_template("addfigure.html", brand=brands, manufacturer=manufacturers)

# ------------------- Add Brand -------------------
@app.route("/add_brand", methods=["GET", "POST"])
def add_brand_route():
    if request.method == "POST":
        error = add_brand(request.form)
        if error:
            flash(error)
        else:
            flash("Brand added successfully.")
            return redirect(url_for("add_brand_route"))

    return render_template("add_brand.html")


# ------------------- Add Manufacturer -------------------
@app.route("/add_manufacturer", methods=["GET", "POST"])
def add_manufacturer_route():
    if request.method == "POST":
        error = add_manufacturer(request.form)
        if error:
            flash(error)
        else:
            flash("Manufacturer added successfully.")
            return redirect(url_for("add_manufacturer_route"))

    return render_template("add_manufacturer.html")
    
# ------------------- Search -------------------
@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "").strip()

    # limit input size (prevents abuse)
    if len(query) > 100:
        query = query[:100]

    user_results = User.query.filter(
        User.username.ilike(f"%{query}%")
    ).all()

    figure_results = Figures.query.filter(
        (Figures.name.ilike(f"%{query}%")) |
        (Figures.genre.ilike(f"%{query}%")) |
        (Figures.series.ilike(f"%{query}%"))
    ).all()

    return render_template(
        "search.html",
        query=query,
        user_results=user_results,
        figure_results=figure_results
    )

# ----------------- Login Logs ------------------
@app.route("/loginlogs")
def loginlogs():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()

    
   #-- if user.roleID != 1:  
   #--     return "Access Denied", 403

    logs = LoginLog.query.order_by(LoginLog.attempt_time.desc()).all()
    return render_template("loginlogs.html", logs=logs)

#-------------------- Change Password -----------
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """
    Step 1: user enters email from login alert link
    """
    if request.method == "POST":
        email = request.form.get("email")

        success, error = create_password_reset(email)

        if error:
            flash(error)
            return render_template("change_password_request.html")

        flash("Verification code sent to your email.")
        return redirect(url_for("verify_change_password"))

    return render_template("change_password_request.html")


@app.route("/verify_change_password", methods=["GET", "POST"])
def verify_change_password():
    """
    Step 2: enter email + code
    """
    if request.method == "POST":
        email = request.form.get("email")
        code = request.form.get("code")

        success, error = verify_password_reset_code(email, code)

        if error:
            flash(error)
            return render_template("change_password_verify.html")

        session["reset_email"] = email
        flash("Code verified. You may now reset your password.")
        return redirect(url_for("set_new_password"))

    return render_template("change_password_verify.html")


@app.route("/set_new_password", methods=["GET", "POST"])
def set_new_password():
    """
    Step 3: set new password
    """
    email = session.get("reset_email")

    if not email:
        flash("Session expired. Please restart password reset.")
        return redirect(url_for("change_password"))

    if request.method == "POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("repassword")

        success, error = change_user_password(email, new_password, confirm_password)

        if error:
            flash(error)
            return render_template("change_password.html")

        session.pop("reset_email", None)
        flash("Password updated successfully.")
        return redirect(url_for("home"))

    return render_template("change_password.html")

# ------------------- Account ------------------- 

@app.route("/account")
def account():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()

    collections = UserCollection.query.filter_by(user_id=user.id).all()
    subcollections = SubCollection.query.filter_by(user_id=user.id).all()

    return render_template(
        "account.html",
        collections=collections,
        subcollections=subcollections
    )

# ------------------- Collections ------------------- 

@app.route("/my_collection")
def my_collection():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    items = UserCollection.query.filter_by(user_id=user.id).all()

    figures = []
    for item in items:
        fig = Figures.query.get(item.figure_id)
        if fig:
            figures.append(fig)

    return render_template("my_collection.html", figures=figures)
    
@app.route("/add_collection", methods=["GET", "POST"])
def add_collection():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    query = request.args.get("q", "").strip()

    results = []
    if query:
        results = Figures.query.filter(
            Figures.name.ilike(f"%{query}%")
        ).all()

    if request.method == "POST":
        figure_id = request.form.get("figure_id")

        if not figure_id:
            return redirect(url_for("add_collection"))

        # prevent duplicates
        exists = UserCollection.query.filter_by(
            user_id=user.id,
            figure_id=figure_id
        ).first()

        if not exists:
            db.session.add(UserCollection(
                user_id=user.id,
                figure_id=figure_id
            ))
            db.session.commit()

        return redirect(url_for("add_collection"))

    return render_template("add_collection.html", results=results)
    
    
@app.route("/create_subcollection", methods=["GET", "POST"])
def create_subcollection():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    figures = UserCollection.query.filter_by(user_id=user.id).all()

    if request.method == "POST":
        title = request.form.get("title", "").strip()

        if not title:
            return render_template("create_subcollection.html", figures=figures, message="Title required")

        sub = SubCollection(user_id=user.id, title=title)
        db.session.add(sub)
        db.session.commit()

        return redirect(url_for("account"))

    return render_template("create_subcollection.html", figures=figures)

@app.route("/subcollection/add", methods=["POST"])
def add_to_subcollection():
    user = get_current_user()

    sub_id = request.form["subcollection_id"]
    fig_id = request.form["figure_id"]

    # prevent duplicates
    exists = SubCollectionItem.query.filter_by(
        subcollection_id=sub_id,
        figure_id=fig_id
    ).first()

    if not exists:
        db.session.add(SubCollectionItem(
            subcollection_id=sub_id,
            figure_id=fig_id
        ))
        db.session.commit()

    return redirect(url_for("edit_subcollection", id=sub_id))
    
@app.route("/subcollection/<int:id>")
def subcollection(id):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    sub = SubCollection.query.get(id)

    # ownership protection
    if not sub or sub.user_id != user.id:
        return "Access Denied", 403

    items = SubCollectionItem.query.filter_by(subcollection_id=id).all()

    figures = []
    for item in items:
        fig = Figures.query.get(item.figure_id)
        if fig:
            figures.append(fig)

    return render_template("subcollection.html", sub=sub, figures=figures)
    
@app.route("/subcollection/<int:id>/edit", methods=["GET"])
def edit_subcollection(id):
    user = get_current_user()

    subcollection = SubCollection.query.get_or_404(id)

    # ONLY user's figures
    user_figures = (
        db.session.query(Figures)
        .join(UserCollection)
        .filter(UserCollection.user_id == user.id)
        .all()
    )

    # already in subcollection
    existing = {
        item.figure_id
        for item in SubCollectionItem.query.filter_by(subcollection_id=id).all()
    }

    return render_template(
        "edit_subcollection.html",
        subcollection=subcollection,
        figures=user_figures,
        existing=existing
    )
    
# ------------------- Admin ------------------- 

@app.route("/admin")
def admin():
  
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session.get("username")).first()

    if not user:
        session.clear()
        return redirect(url_for("login"))

 
    if not user_has_permission(user, 1):
        return "Access Denied: Admin permissions required.", 403

  
    roles = Roles.query.all()
    permissions = Permissions.query.all()
    users = User.query.all()

    return render_template(
        "admin.html",
        roles=roles,
        permissions=permissions,
        users=users
    )
    
# ------------------- Run App -------------------
if __name__ == "__main__":
    app.run(debug=True)