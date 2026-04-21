# --- HonoursProject.py ---
# --- Imports ---
from flask import Flask, request, redirect, url_for, flash, session, render_template, send_from_directory
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import random
from flask_migrate import Migrate
# --- Imports from project
from models.models import db, User, Roles, Permissions, RolePermissions, Figures, FigureImages, UserCollection, SubCollection, SubCollectionItem, LoginLog, Brand, Manufacturer
from services.user_service import get_current_user, register_user, authenticate_user, get_all_users_with_permissions, user_has_permission, verify_signup_code, verify_login_code, log_login_attempt, create_password_reset, verify_password_reset_code, change_user_password
from services.role_service import create_permission, create_role, assign_permission_to_role, assign_role_to_user
from services.figure_service import add_figure, add_brand, add_manufacturer, get_all_brands, get_all_manufacturers
from services.email_service import send_verification_email
from config import PROFILE_PICS_FOLDER, UPLOAD_FOLDER, ALLOWED_EXTENSIONS


# --- Extension check
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    
# ------------------- Flask App -------------------
app = Flask(__name__)
app.secret_key = "your_secret_key"
migrate = Migrate(app, db)

# ------------------- Database Setup -------------------

# MySQL Configuration
DB_USER = "root"             
DB_PASSWORD = "password"     
DB_HOST = "localhost"
DB_NAME = "honours_db"    

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:Thecaptain2004!@localhost:3306/honours_db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

# ------------------- Create Database Tables -------------------
with app.app_context():
    db.create_all()

# ------------------- Static Folders -------------------
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

# ------------------ Nav -------------------
@app.route("/nav")
def nav():
    return render_template("nav.html")
    
# ------------------- Home -------------------
@app.route("/home")
def home():
    user = None
    if session.get("logged_in"):
        user = User.query.filter_by(username=session.get("username")).first()

    return render_template(
        "home.html",
        logged_in=session.get("logged_in", False),
        username=session.get("username"),
        profile_pic=user.profile_pic if user else None
    )

# ------------------- Signup with 2FA -------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        form_data = request.form
        user_info, error = register_user(request.form, request.files)
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

        # NO EMAIL
        if not email:
            flash("No signup attempt found. Please signup again.")
            return redirect(url_for("signup"))

        # WRONG CODE
        user, error = verify_signup_code(email, entered_code)
        if error:
            flash(error)
            return render_template("signup_verify.html")
        
        # CORRECT CODE
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

        # USER NOT FOUND
        if not user:
            log_login_attempt(None, username, False)
            return render_template("login.html", message="Account does not exist.")

        # ACCOUNT LOCKED
        if user.lockout_until and datetime.utcnow() < user.lockout_until:
            log_login_attempt(user, username, False, timed_out=True)
            return render_template("login.html", message="Account locked. Try again later.")

        # WRONG PASSWORD
        if not user.check_password(password):
            user.failed_attempts += 1

            # LOCK AFTER 3 FAILS
            if user.failed_attempts >= 3:
                user.lockout_until = datetime.utcnow() + timedelta(minutes=10)
                db.session.commit()

                log_login_attempt(user, username, False, timed_out=True)
                return render_template("login.html", message="Too many attempts. Locked for 10 minutes.")

            db.session.commit()
            log_login_attempt(user, username, False)
            return render_template("login.html", message="Password incorrect.")

        # PASSWORD CORRECT
        user.failed_attempts = 0
        user.lockout_until = None
        db.session.commit()

        log_login_attempt(user, username, True)

        # 2FA CODE
        code = str(random.randint(100000, 999999))

        session["login_username"] = user.username
        session["login_email"] = user.email
        session["login_code"] = code
        session["login_attempts"] = 0

        send_verification_email(user.email, code, subject="Login Verification Code")

        flash("2FA code sent to your email.")
        return redirect(url_for("verify_login"))

    # GET request
    return render_template("login.html")

@app.route("/verify_login", methods=["GET", "POST"])
def verify_login():
    if request.method == "POST":
        entered_code = request.form.get("code")
        email = session.get("login_email")

        # NO LOGIN ATTEMPT
        if not email:
            flash("No login attempt found. Please login again.")
            return redirect(url_for("login"))

        # CORRECT CODE
        if entered_code == session.get("login_code"):
            username = session.pop("login_username", None)
            session.pop("login_email", None)
            session.pop("login_code", None)
            session.pop("login_attempts", None)

            user = User.query.filter_by(username=username).first()
            session["logged_in"] = True
            session["username"] = username
            session["profile_pic"] = user.profile_pic or "default_pfp.jpg"
            flash("Login successful!")
            return redirect(url_for("home"))
            
            # WRONG CODE
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

    # DISPLAY ALL USERS IN THE 'USERS' TABLE
    user = User.query.filter_by(username=session.get("username")).first()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # CHECK CURRENT USER'S PERMISSIONS
    if not user_has_permission(user, 6):
        return "Access Denied: Permission required.", 403

    current_user = User.query.filter_by(username=session["username"]).first()
    users_list = get_all_users_with_permissions(current_user)
    return render_template("users.html", users=users_list)

# ------------------- Permissions & Roles -------------------
@app.route("/permcreate", methods=["GET", "POST"])
def permcreate():
 
    # CHECK IF LOGGED IN
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session.get("username")).first()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    
    # CHECK USER PERMISSION
    if not user_has_permission(user, 2):
        return "Access Denied: Permission required.", 403
    
    # CREATE PERMISSION
    if request.method == "POST":
        error = create_permission(request.form["permName"], request.form["permDesc"])
        
        if error:
            flash(error, "error")
        else:
            flash("Permission created successfully.", "success")

    return render_template("permcreate.html")


@app.route("/rolecreate", methods=["GET", "POST"])
def rolecreate():
    
    # CHECK IF LOGGED IN
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session.get("username")).first()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # CHECK USER PERMISSION
    if not user_has_permission(user, 3):
        return "Access Denied: Permission required.", 403
    
    # CREATE ROLE
    if request.method == "POST":
        error = create_role(request.form["roleName"], request.form["roleDesc"])

        if error:
            flash(error, "error")
        else:
            flash("Role created successfully.", "success")

    return render_template("rolecreate.html")


@app.route("/roleassign", methods=["GET", "POST"])
def roleassign():
    
    # CHECK IF LOGGED IN
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session.get("username")).first()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # CHECK USER PERMISSION
    if not user_has_permission(user, 4):
        return "Access Denied: Permission required.", 403
        
    roles = Roles.query.all()
    perms = Permissions.query.all()

    # ASSIGN PERMISSION TO ROLE
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
    
    # CHECK IF LOGGED IN
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session.get("username")).first()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # CHECK USER PERMISSION
    if not user_has_permission(user, 5):
        return "Access Denied: Permission required.", 403
      
    # ASSIGN ROLE TO USER
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
    
    # CHECK IF LOGGED IN
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session.get("username")).first()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # CHECK USER PERMISSION
    if not user_has_permission(user, 7):
        return "Access Denied: Permission required.", 403
        
    brands = get_all_brands()
    manufacturers = get_all_manufacturers()

    # ADD FIGURE
    if request.method == "POST":
        error = add_figure(request.form)

        if error:
            flash(error)
            return render_template("addfigure.html", brand=brands, manufacturer=manufacturers)

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
def add_brand():
    # CHECK IF LOGGED IN
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session.get("username")).first()

    # CHECK USER PERMISSION
    if not user_has_permission(user, 8):
        return "Access Denied: Permission required.", 403

    # ADD BRAND
    if request.method == "POST":
        error = add_brand_service(request.form)
        if error:
            flash(error)
        else:
            flash("Brand added successfully.")
            return redirect(url_for("add_brand"))

    return render_template("add_brand.html")


# ------------------- Add Manufacturer -------------------
@app.route("/add_manufacturer", methods=["GET", "POST"])
def add_manufacturer():
    
    # CHECK IF LOGGED IN
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session.get("username")).first()

    # CHECK USER PERMISSION
    if not user_has_permission(user, 9):
        return "Access Denied: Permission required.", 403

    # ADD MANUFACTURER
    if request.method == "POST":
        error = add_manufacturer_service(request.form)
        if error:
            flash(error)
        else:
            flash("Manufacturer added successfully.")
            return redirect(url_for("add_manufacturer"))

    return render_template("add_manufacturer.html")
    
# ------------------- Search -------------------
@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "").strip()

    # LIMIT INPUT SIZE
    if len(query) > 100:
        query = query[:100]

    # SEARCH FOR USERNAMES IN USERS' TABLE
    user_results = User.query.filter(
        User.username.ilike(f"%{query}%")
    ).all()

    # SEARCH FOR VARIOUS FIGURE INFO
    figure_results = Figures.query.join(Brand).join(Manufacturer).filter(
        (
            Figures.name.ilike(f"%{query}%")
        ) |
        (
            Figures.genre.ilike(f"%{query}%")
        ) |
        (
            Figures.series.ilike(f"%{query}%")
        ) |
        (
            Brand.name.ilike(f"%{query}%")
        ) |
        (
            Manufacturer.name.ilike(f"%{query}%")
        )
    ).distinct().all()

    return render_template(
        "search.html",
        query=query,
        user_results=user_results,
        figure_results=figure_results
    )

# ----------------- Login Logs ------------------
@app.route("/loginlogs")
def loginlogs():
        
    # CHECK IF LOGGED IN
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()

    # CHECK USER PERMISSION
    if not user_has_permission(user, 10):
        return "Access Denied: Permission required.", 403

    # DISPLAY CONTENT FROM LOGINLOGS TABLE
    logs = LoginLog.query.order_by(LoginLog.attempt_time.desc()).all()
    return render_template("loginlogs.html", logs=logs)

#-------------------- Change Password -----------
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """
    Step 1: user enters email from login alert link
    """
    # GETS EMAIL FROM USER
    if request.method == "POST":
        email = request.form.get("email")

        success, error = create_password_reset(email)

        # IF INCORRECT GIVE ERROR
        if error:
            flash(error)
            return render_template("change_password_request.html")

        # IF CORRECT SEND VERIFICATION CODE AND PROCEED
        flash("Verification code sent to your email.")
        return redirect(url_for("verify_change_password"))

    return render_template("change_password_request.html")


@app.route("/verify_change_password", methods=["GET", "POST"])
def verify_change_password():
    """
    Step 2: enter email + code
    """
    # GET CODE FROM USER
    if request.method == "POST":
        code = request.form.get("code")

        email = session.get("reset_email")
        success, error = verify_password_reset_code(email, code)

        # IF INCORRECT GIVE ERROR
        if error:
            flash(error)
            return render_template("change_password_verify.html")

        # IF CORRECT PROCEED TO CHANGE PASSWORD
        flash("Code verified. You may now reset your password.")
        return redirect(url_for("set_new_password"))

    return render_template("change_password_verify.html")


@app.route("/set_new_password", methods=["GET", "POST"])
def set_new_password():
    
    # CHECK IF CURRENT USER HAS THE RESET EMAIL
    email = session.get("reset_email")

    # IF NOT, RESTART PROCESS
    if not email:
        flash("Session expired. Please restart password reset.")
        return redirect(url_for("change_password"))

    # IF YES, LET THEM CHANGE PASSWORD
    if request.method == "POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("repassword")

        # GIVE ERROR IF PASSWORD DOESN'T MEET REQUIREMENTS
        success, error = change_user_password(email, new_password, confirm_password)

        if error:
            flash(error)
            return render_template("change_password_verify.html")
        
        # REST PASSWORD IF CONDITIONS ARE MET
        session.pop("reset_email", None)

        return "updated successfully"

    return render_template("change_password.html")
    
# ------------------- Account ------------------- 

@app.route("/account")
def account():
    
    # GET CURRENT USER
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for("login"))

    profile_user = User.query.filter_by(username=session["username"]).first()

    collections = UserCollection.query.filter_by(user_id=current_user.id).all()
    subcollections = SubCollection.query.filter_by(user_id=current_user.id).all()

    return render_template(
        "account.html",
        profile_user=profile_user,
        collections=collections,
        subcollections=subcollections
    )

@app.route("/account/<username>")
def view_account(username):
    
    # GET CURRENT USER
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for("login"))

    # REDIRECT IF CURRENT USER'S ACCOUNT
    if current_user.username == username:
        return redirect(url_for("account"))

    profile_user = User.query.filter_by(username=username).first()

    # ERROR IF USER DOESN'T EXIST
    if not profile_user:
        return "User not found", 404

    # GET FULL FIGURE OBJECTS 
    collection_items = UserCollection.query.filter_by(user_id=profile_user.id).all()

    figures = []
    for item in collection_items:
        fig = Figures.query.get(item.figure_id)
        if fig:
            figures.append(fig)

    subcollections = SubCollection.query.filter_by(user_id=profile_user.id).all()

    return render_template(
        "account_view.html",
        profile_user=profile_user,
        figures=figures,
        subcollections=subcollections
    )
    
@app.route("/account/<username>/subcollection/<int:sub_id>")
def view_public_subcollection(username, sub_id):
    
    # GET CURRENT USER
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for("login"))

    profile_user = User.query.filter_by(username=username).first()
    if not profile_user:
        return "User not found", 404

    sub = SubCollection.query.get(sub_id)

    # OWNERSHIP CHECK
    if not sub or sub.user_id != profile_user.id:
        return "Subcollection not found", 404

    # GET FIGURES IN SUBCOLLECTION
    items = SubCollectionItem.query.filter_by(subcollection_id=sub_id).all()

    figures = []
    for item in items:
        fig = Figures.query.get(item.figure_id)
        if fig:
            figures.append(fig)

    return render_template(
        "subcollection_view.html",
        profile_user=profile_user,
        sub=sub,
        figures=figures
    )
# ------------------- Collections ------------------- 

@app.route("/my_collection")
def my_collection():
    
    # GET CURRENT USER
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    # GET ALL FIGURES IN USERCOLLECTION
    items = UserCollection.query.filter_by(user_id=user.id).all()

    figures = []
    for item in items:
        fig = Figures.query.get(item.figure_id)
        if fig:
            figures.append(fig)

    return render_template("my_collection.html", figures=figures)
    
@app.route("/add_collection", methods=["GET", "POST"])
def add_collection():
    
    # GET CURRENT USER
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    # ADD FIGURE TO COLLECTION
    if request.method == "POST":
        figure_id = request.form.get("figure_id")

        if figure_id:
            exists = UserCollection.query.filter_by(
                user_id=user.id,
                figure_id=figure_id
            ).first()

            # ONLY ADD IF FIGURE IS NOT IN THE COLLECTION
            if not exists:
                db.session.add(UserCollection(
                    user_id=user.id,
                    figure_id=figure_id
                ))
                db.session.commit()

        return redirect(url_for("add_collection"))

 
    # SEARCH FOR FIGURES IN THE  DB
    query = request.args.get("q", "")

    if query:
        results = Figures.query.filter(
            Figures.name.ilike(f"%{query}%")
        ).all()
    else:
        results = []

    existing_ids = set(
        row.figure_id
        for row in UserCollection.query.filter_by(user_id=user.id).all()
    )

    return render_template(
        "add_collection.html",
        results=results,
        existing_ids=existing_ids,
        query=query
    )
    
    
@app.route("/create_subcollection", methods=["GET", "POST"])
def create_subcollection():
    
    # GET CURRENT USER
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    # SHOW PAGE
    if request.method == "GET":

        user_figures = (
            db.session.query(Figures)
            .join(UserCollection, UserCollection.figure_id == Figures.id)
            .filter(UserCollection.user_id == user.id)
            .all()
        )

        return render_template(
            "create_subcollection.html",
            figures=user_figures
        )

    # TITLE SUBCOLLECTION
    title = request.form.get("title", "").strip()
    if not title:
        return render_template(
            "create_subcollection.html",
            figures=[],
            message="Title is required"
        )

    # IMAGE UPLOAD
    file = request.files.get("image")
    filename = None

    if file and file.filename:
        filename = secure_filename(file.filename)
        path = os.path.join("static/subimg", filename)
        file.save(path)

    # CREATE SUBCOLLECTION
    sub = SubCollection(
        user_id=user.id,
        title=title,
        image=filename
    )

    db.session.add(sub)
    db.session.commit()  

    # SELECT FIGURES FROM USERCOLLECTION
    figure_ids = request.form.getlist("figure_ids")

    single_id = request.form.get("figure_id")
    if single_id and not figure_ids:
        figure_ids = [single_id]

    for fid in figure_ids:
        db.session.add(SubCollectionItem(
            subcollection_id=sub.id,
            figure_id=int(fid)
        ))

    db.session.commit()

    return redirect(url_for("account"))
    
@app.route("/subcollection/add", methods=["POST"])
def add_to_subcollection():
    user = get_current_user()

    sub_id = request.form["subcollection_id"]
    fig_id = request.form["figure_id"]

    # PREVENT DUPLICATES
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
    
    # GET CURRENT USER
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    sub = SubCollection.query.get(id)

    # OWNERSHIP PROTECTION
    if not sub or sub.user_id != user.id:
        return "Access Denied", 403

    items = SubCollectionItem.query.filter_by(subcollection_id=id).all()

    figures = []
    for item in items:
        fig = Figures.query.get(item.figure_id)
        if fig:
            figures.append(fig)

    return render_template("subcollection.html", sub=sub, figures=figures)
    
@app.route("/subcollection/<int:id>/edit", methods=["GET", "POST"])
def edit_subcollection(id):
    user = get_current_user()

    subcollection = SubCollection.query.get_or_404(id)

    if subcollection.user_id != user.id:
        return "Access Denied", 403

    # EDIT SUBCOLLECTION
    if request.method == "POST":

        action = request.form.get("action")

        # UPDATE TITLE AND IMAGE
        if action == "update":
            subcollection.title = request.form.get("title")

            file = request.files.get("image")
            if file and file.filename:
                filename = secure_filename(file.filename)
                path = os.path.join("static/subimg", filename)
                file.save(path)
                subcollection.image = filename

            db.session.commit()
            return redirect(url_for("edit_subcollection", id=id))

        # ADD FIGURE
        if action == "add":
            fig_id = int(request.form.get("figure_id"))

            exists = SubCollectionItem.query.filter_by(
                subcollection_id=id,
                figure_id=fig_id
            ).first()

            if not exists:
                db.session.add(SubCollectionItem(
                    subcollection_id=id,
                    figure_id=fig_id
                ))
                db.session.commit()

            return redirect(url_for("edit_subcollection", id=id))

        # REMOVE FIGURE
        if action == "remove":
            fig_id = int(request.form.get("figure_id"))

            link = SubCollectionItem.query.filter_by(
                subcollection_id=id,
                figure_id=fig_id
            ).first()

            if link:
                db.session.delete(link)
                db.session.commit()

            return redirect(url_for("edit_subcollection", id=id))

        # DELETE SUBCOLLECTION
        if action == "delete":
            SubCollectionItem.query.filter_by(subcollection_id=id).delete()
            db.session.delete(subcollection)
            db.session.commit()
            return redirect(url_for("account"))

    user_figures = (
        db.session.query(Figures)
        .join(UserCollection)
        .filter(UserCollection.user_id == user.id)
        .all()
    )

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
  
    # GET CURRENT USER
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session.get("username")).first()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    # CHECK USER PERMISSION
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
 
# ------------------- Figure -------------------
@app.route("/figure/<int:figure_id>")
def figure_view(figure_id):
    fig = Figures.query.get_or_404(figure_id)

    return render_template(
        "figure_view.html",
        fig=fig
    ) 
    
# ------------------- Run App -------------------
if __name__ == "__main__":
    app.run(debug=True)
    
