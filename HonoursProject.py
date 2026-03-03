from flask import Flask, request, redirect, url_for, flash, session, render_template, send_from_directory
from models.models import db, User, Figures
from services.user_service import register_user, authenticate_user, get_all_users_with_permissions, verify_signup_code, verify_login_code
from services.role_service import create_permission, create_role, assign_permission_to_role, assign_role_to_user
from services.figure_service import add_figure, get_all_brands, get_all_manufacturers
from services.email_service import send_verification_email
import os
import random

# ------------------- Flask App -------------------
app = Flask(__name__)
app.secret_key = "your_secret_key"

# ------------------- Database Setup -------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, "Honours.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# ------------------- Static Folders -------------------
PROFILE_PICS_FOLDER = os.path.join(BASE_DIR, "static", "profile_pics")
os.makedirs(PROFILE_PICS_FOLDER, exist_ok=True)

@app.route("/profile_pics/<filename>")
def profile_pics(filename):
    return send_from_directory(PROFILE_PICS_FOLDER, filename)

# ------------------- Home -------------------
@app.route("/")
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
        return redirect(url_for("login"))

    return render_template("signup_verify.html")

# ------------------- Login with 2FA -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template("login.html", message="Account does not exist.")
        if not user.check_password(password):
            return render_template("login.html", message="Password incorrect.")

        # Generate 2FA code
        code = str(random.randint(100000, 999999))

        # Store code and username in session for verification
        session["login_username"] = user.username
        session["login_email"] = user.email
        session["login_code"] = code
        session["login_attempts"] = 0

        # Send email once
        send_verification_email(user.email, code, subject="Login Verification Code")

        flash("2FA code sent to your email.")
        return redirect(url_for("verify_login"))

    return render_template("login.html")


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
        flash(error if error else "Permission created successfully.")
    return render_template("permcreate.html")


@app.route("/rolecreate", methods=["GET", "POST"])
def rolecreate():
    if request.method == "POST":
        error = create_role(request.form["roleName"], request.form["roleDesc"])
        flash(error if error else "Role created successfully.")
    return render_template("rolecreate.html")


@app.route("/roleassign", methods=["GET", "POST"])
def roleassign():
    if request.method == "POST":
        error = assign_permission_to_role(request.form["roleName"], request.form["permName"])
        flash(error if error else "Permission assigned successfully.")
    return render_template("roleassign.html")


@app.route("/assignuser", methods=["GET", "POST"])
def assignuser():
    if request.method == "POST":
        error = assign_role_to_user(request.form["username"], request.form["role_id"])
        flash(error if error else "Role assigned successfully.")
    return render_template("assignuser.html")

# ------------------- Add Figure -------------------
@app.route("/addfigure", methods=["GET", "POST"])
def addfigure():
    brands = get_all_brands()
    manufacturers = get_all_manufacturers()
    if request.method == "POST":
        error = add_figure(request.form)
        flash(error if error else "Figure added successfully.")
        if not error:
            return redirect(url_for("addfigure"))
    return render_template("addfigure.html", brand=brands, manufacturer=manufacturers)

# ------------------- Search -------------------
@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "").strip()
    user_results = User.query.filter(User.username.ilike(f"%{query}%")).all()
    figure_results = Figures.query.filter(
        Figures.name.ilike(f"%{query}%") |
        Figures.genre.ilike(f"%{query}%") |
        Figures.series.ilike(f"%{query}%")
    ).all()
    return render_template(
        "search.html",
        query=query,
        user_results=user_results,
        figure_results=figure_results
    )

# ------------------- Run App -------------------
if __name__ == "__main__":
    with app.app_context():
        os.makedirs("instance", exist_ok=True)
        db.create_all()
    app.run(debug=True)