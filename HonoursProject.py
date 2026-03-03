import os
from flask import Flask, request, redirect, url_for, flash, session, render_template, send_from_directory
from models.models import db, User, Figures, Brand, Manufacturer
from services.user_service import (
    register_user,
    authenticate_user,
    get_all_users_with_permissions
)
from services.role_service import (
    create_permission,
    create_role,
    assign_permission_to_role,
    assign_role_to_user
)
from services.figure_service import (
    add_figure, 
    get_all_brands,  
    get_all_manufacturers
)
# ------------------- App Setup -------------------
app = Flask(__name__)
app.secret_key = "your_secret_key"

# Database folder
INSTANCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(INSTANCE_DIR, 'Honours.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Profile pictures folder
PROPIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profile_pics")
os.makedirs(PROPIC_DIR, exist_ok=True)

# Initialize database
db.init_app(app)

# ------------------- Profile Picture Route -------------------
@app.route('/profile_pics/<filename>')
def profile_pics(filename):
    return send_from_directory(PROPIC_DIR, filename)

# ------------------- Home -------------------
@app.route("/")
def home():
    return render_template(
        "home.html",
        logged_in=session.get("logged_in", False),
        username=session.get("username"),
        profile_pic=session.get("profile_pic", "default_pfp.png")
    )

# ------------------- Signup -------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        error = register_user(request.form)
        if error:
            flash(error)
        else:
            return redirect(url_for("login"))
    return render_template("signup.html")

# ------------------- Login -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    if request.method == "POST":
        user, error = authenticate_user(
            request.form["username"],
            request.form["password"]
        )
        if error:
            message = error
        else:
            session["logged_in"] = True
            session["username"] = user.username
            session["profile_pic"] = getattr(user, "profile_pic", "default_pfp.png")
            return redirect(url_for("home"))
    return render_template("login.html", message=message)

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

    current_user = User.query.filter_by(username=session.get("username")).first()
    users_list = get_all_users_with_permissions(current_user)
    return render_template("users.html", users=users_list)

# ------------------- Permissions -------------------
@app.route("/permcreate", methods=["GET", "POST"])
def permcreate():
    if request.method == "POST":
        error = create_permission(
            request.form["permName"],
            request.form["permDesc"]
        )
        if error:
            flash(error)
        else:
            flash("Permission created successfully.")
    return render_template("permcreate.html")

# ------------------- Roles -------------------
@app.route("/rolecreate", methods=["GET", "POST"])
def rolecreate():
    if request.method == "POST":
        error = create_role(
            request.form["roleName"],
            request.form["roleDesc"]
        )
        if error:
            flash(error)
        else:
            flash("Role created successfully.")
    return render_template("rolecreate.html")

# ------------------- Assign Permission to Role -------------------
@app.route("/roleassign", methods=["GET", "POST"])
def roleassign():
    if request.method == "POST":
        error = assign_permission_to_role(
            request.form["roleName"],
            request.form["permName"]
        )
        if error:
            flash(error)
        else:
            flash("Permission assigned successfully.")
    return render_template("roleassign.html")

# ------------------- Assign Role to User -------------------
@app.route("/assignuser", methods=["GET", "POST"])
def assignuser():
    if request.method == "POST":
        error = assign_role_to_user(
            request.form["username"],
            request.form["role_id"]
        )
        if error:
            flash(error)
        else:
            flash("Role assigned successfully.")
    return render_template("assignuser.html")

# ------------------- Add Figure -------------------
@app.route("/addfigure", methods=["GET", "POST"])
def addfigure():
    brands = get_all_brands()
    manufacturers = get_all_manufacturers()

    if request.method == "POST":
        error = add_figure(request.form)
        if error:
            flash(error)
        else:
            flash("Figure added successfully.")
            return redirect(url_for("addfigure"))

    return render_template("addfigure.html", brand=brands, manufacturer=manufacturers)

# ------------------- Search -------------------
@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "").strip()
    user_results = []
    figure_results = []

    if query:
        # Search users
        user_results = User.query.filter(User.username.ilike(f"%{query}%")).all()
        # Search figures
        figure_results = Figures.query.filter(
            db.or_(
                Figures.name.ilike(f"%{query}%"),
                Figures.genre.ilike(f"%{query}%"),
                Figures.series.ilike(f"%{query}%")
            )
        ).all()

    return render_template(
        "search.html",
        query=query,
        user_results=user_results,
        figure_results=figure_results
    )

# ------------------- Database Initialization -------------------
def initialize_db():
    with app.app_context():
        if not os.path.exists(os.path.join(INSTANCE_DIR, "Honours.db")):
            open(os.path.join(INSTANCE_DIR, "Honours.db"), "a").close()
        db.create_all()

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)