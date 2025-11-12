from flask import Flask, request, redirect, url_for, flash, session, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

# ------------------- App Setup -------------------
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Directories
INSTANCE_DIR = os.path.join(os.path.dirname(__file__), "instance")
PROPIC_DIR = os.path.join(os.path.dirname(__file__), "profile_pics")
os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(PROPIC_DIR, exist_ok=True)
DB_FILE = os.path.join(INSTANCE_DIR, "Honours.db")

# Database config
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_FILE}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

KEY_FILE = os.path.join(INSTANCE_DIR, "secret.key")

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(ENCRYPTION_KEY)

fernet = Fernet(ENCRYPTION_KEY)


# ------------------- Models -------------------

# User table
class User(db.Model):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    _surname = db.Column("surname", db.LargeBinary, nullable=False)
    _forename = db.Column("forename", db.LargeBinary, nullable=False)
    _email = db.Column("email", db.LargeBinary, unique=True, nullable=False)
    _dob = db.Column("dob", db.LargeBinary, nullable=False)
    _country = db.Column("country", db.LargeBinary, nullable=False)
    _bio = db.Column("bio", db.LargeBinary, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    profile_pic = db.Column(db.String(255), nullable=True)
    roleID = db.Column(db.Integer, db.ForeignKey('Roles.id'), nullable=True)

    # Password handling
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    # Encryption helpers
    def encrypt(self, value):
        return fernet.encrypt(value.encode()) if value else None

    def decrypt(self, value):
        if not value:
            return None
        try:
            return fernet.decrypt(value).decode()
        except Exception:
            return "[Invalid or old data]"


    # Properties
    @property
    def surname(self): return self.decrypt(self._surname)
    @surname.setter
    def surname(self, value): self._surname = self.encrypt(value)

    @property
    def forename(self): return self.decrypt(self._forename)
    @forename.setter
    def forename(self, value): self._forename = self.encrypt(value)

    @property
    def email(self): return self.decrypt(self._email)
    @email.setter
    def email(self, value): self._email = self.encrypt(value)

    @property
    def dob(self): return self.decrypt(self._dob)
    @dob.setter
    def dob(self, value): self._dob = self.encrypt(value)

    @property
    def country(self): return self.decrypt(self._country)
    @country.setter
    def country(self, value): self._country = self.encrypt(value)

    @property
    def bio(self): return self.decrypt(self._bio) if self._bio else None
    @bio.setter
    def bio(self, value): self._bio = self.encrypt(value) if value else None


# Roles, Permissions, RolePermissions
class Roles(db.Model):
    __tablename__ = 'Roles'
    id = db.Column(db.Integer, primary_key=True)
    roleName = db.Column(db.String(20), unique=True, nullable=False)
    roleDesc = db.Column(db.String(200), unique=True, nullable=False)
    permissions = db.relationship('Permissions', secondary='RolePermissions', back_populates='roles')


class Permissions(db.Model):
    __tablename__ = 'Permissions'
    id = db.Column(db.Integer, primary_key=True)
    permName = db.Column(db.String(20), unique=True, nullable=False)
    permDesc = db.Column(db.String(100), unique=True, nullable=False)
    roles = db.relationship('Roles', secondary='RolePermissions', back_populates='permissions')


class RolePermissions(db.Model):
    __tablename__ = 'RolePermissions'
    roleID = db.Column(db.Integer, db.ForeignKey('Roles.id'), primary_key=True)
    permissionsID = db.Column(db.Integer, db.ForeignKey('Permissions.id'), primary_key=True)


# Figures and Collections
class Figures(db.Model):
    __tablename__ = 'Figures'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    desc = db.Column(db.String(1000), nullable=False)
    brandID = db.Column(db.Integer, db.ForeignKey('Brand.id'), nullable=False)
    manufacturerID = db.Column(db.Integer, db.ForeignKey('Manufacturer.id'), nullable=False)
    genre = db.Column(db.String(50), nullable=False)
    series = db.Column(db.String(50), nullable=False)
    figCode = db.Column(db.Integer, nullable=False)
    janCode = db.Column(db.Integer, nullable=False)
    releaseDate = db.Column(db.Integer, nullable=False)
    retailPrice = db.Column(db.Integer, nullable=False)
    avgPrice = db.Column(db.Integer, nullable=False)
    itemSize = db.Column(db.Integer, nullable=False)
    itemWeight = db.Column(db.Integer, nullable=False)
    links = db.Column(db.String(2000), nullable=False)
    collection = db.relationship('Collection', secondary='FigureCollection', back_populates='figures')


class Brand(db.Model):
    __tablename__ = 'Brand'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    desc = db.Column(db.String(1000), unique=True, nullable=False)
    manufacturerID = db.Column(db.Integer, db.ForeignKey('Manufacturer.id'), nullable=False)


class Manufacturer(db.Model):
    __tablename__ = 'Manufacturer'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    desc = db.Column(db.String(1000), unique=True, nullable=False)


class Collection(db.Model):
    __tablename__ = 'Collection'
    id = db.Column(db.Integer, primary_key=True)
    figures = db.relationship('Figures', secondary='FigureCollection', back_populates='collection')
    worth = db.Column(db.Integer, nullable=False)
    userID = db.Column(db.Integer, db.ForeignKey('User.id'))


class FigureCollection(db.Model):
    __tablename__ = 'FigureCollection'
    figuresID = db.Column(db.Integer, db.ForeignKey('Figures.id'), primary_key=True)
    collectionID = db.Column(db.Integer, db.ForeignKey('Collection.id'), primary_key=True)


# ------------------- Routes -------------------
# Role and Permission routes
## Permission Creator
@app.route('/permcreate', methods=["GET", "POST"])
def permcreate():
    message = None
    if request.method == "POST":
        permName = request.form.get("permName")
        permDesc = request.form.get("permDesc")
        existing_perm = Permissions.query.filter_by(permName=permName).first()
        if existing_perm:
            message = "Permission already exists!"
        elif not permName or not permDesc:
            message = "Both fields are required."
        else:
            db.session.add(Permissions(permName=permName, permDesc=permDesc))
            db.session.commit()
            message = f"Permission '{permName}' created successfully!"
    return render_template("permcreate.html", message=message)

## Role Creator
@app.route('/rolecreate', methods=["GET", "POST"])
def rolecreate():
    message = None
    if request.method == "POST":
        roleName = request.form.get("roleName")
        roleDesc = request.form.get("roleDesc")
        existing_role = Roles.query.filter_by(roleName=roleName).first()
        if existing_role:
            message = "Role already exists!"
        elif not roleName or not roleDesc:
            message = "Both fields are required."
        else:
            db.session.add(Roles(roleName=roleName, roleDesc=roleDesc))
            db.session.commit()
            message = f"The role '{roleName}' has been created successfully!"
    return render_template("rolecreate.html", message=message)

## Role Assigner
@app.route("/roleassign", methods=["GET", "POST"])
def roleassign():
    message = None
    if request.method == "POST":
        roleName = request.form.get("roleName").strip()
        permName = request.form.get("permName").strip()
        role = Roles.query.filter_by(roleName=roleName).first()
        perm = Permissions.query.filter_by(permName=permName).first()
        if not role:
            message = f"Role '{roleName}' does not exist."
        elif not perm:
            message = f"Permission '{permName}' does not exist."
        else:
            existing = RolePermissions.query.filter_by(roleID=role.id, permissionsID=perm.id).first()
            if existing:
                message = f"Permission '{permName}' already assigned to role '{roleName}'."
            else:
                db.session.add(RolePermissions(roleID=role.id, permissionsID=perm.id))
                db.session.commit()
                message = f"Permission '{permName}' successfully assigned to role '{roleName}'."

    all_roles = Roles.query.all()
    all_perms = Permissions.query.all()
    return render_template("roleassign.html", message=message, roles=all_roles, perms=all_perms)
    
@app.route('/profile_pics/<filename>')
def profile_pics(filename):
    return send_from_directory(PROPIC_DIR, filename)

def user_has_permission(user: User, perm_id: int) -> bool:
    """Check if the user has a given permission by ID."""
    if not user.roleID:
        return False
    role = Roles.query.get(user.roleID)
    if not role:
        return False
    return any(p.id == perm_id for p in role.permissions)

# User Assigner
@app.route("/assignuser", methods=["GET", "POST"])
def assignuser():
    message = None

    # Get all roles for dropdown
    all_roles = Roles.query.all()

    if request.method == "POST":
        username = request.form.get("username").strip()
        role_id = request.form.get("role_id")

        user = User.query.filter_by(username=username).first()
        role = Roles.query.get(role_id)

        if not user:
            message = f"User '{username}' not found."
        elif not role:
            message = "Role not found."
        else:
            user.roleID = role.id
            db.session.commit()
            message = f"Role '{role.roleName}' assigned to user '{user.username}'."

    return render_template("assignuser.html", roles=all_roles, message=message)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        profile_pic = request.files.get("propic")
        pic_filename = None
        if profile_pic and profile_pic.filename:
            pic_filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join(PROPIC_DIR, pic_filename))

        username = request.form["username"]
        surname = request.form["surname"]
        forename = request.form["forename"]
        email = request.form["email"]
        dob = request.form["dob"]
        country = request.form["country"]
        password = request.form["password"]
        repassword = request.form["repassword"]

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()

        if existing_user:
            flash("Username already exists.")
        elif existing_email:
            flash("Email already exists.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        elif password != repassword:
            flash("Passwords must match.")
        else:
            user = User(username=username, surname=surname, forename=forename,
                        email=email, dob=dob, country=country, profile_pic=pic_filename)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("login"))
    return render_template("signup.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if not user:
            message = "Account doesn't exist"
        elif not user.check_password(password):
            message = "Password incorrect"
        else:
            session['logged_in'] = True
            session['username'] = username
            session['profile_pic'] = user.profile_pic if user.profile_pic else "default_pfp.png"
            return redirect(url_for('home'))
    return render_template("home.html", message=message)
    
# Users route
@app.route("/users", methods=["GET"])
def users():
    if not session.get("logged_in"):
        flash("You must be logged in to view users.")
        return redirect(url_for("login"))

    current_user = User.query.filter_by(username=session["username"]).first()
    show_surname = False
    show_forename = False
    show_dob = False
    show_country = False
    show_email = False

    # Check if user has permissionID=1
    if current_user and current_user.roleID:
        role_perms = RolePermissions.query.filter_by(roleID=current_user.roleID).all()
        if any(rp.permissionsID == 1 for rp in role_perms):
            show_surname = True
            show_forename = True
            show_dob = True
            show_country = True
            show_email = True
            
    users_list = []
    for u in User.query.all():
        user_data = {
            "id": u.id,
            "username": u.username,
            "bio": u.bio,
            "roleID": u.roleID,
            "profile_pic": u.profile_pic
        }
        
        ## Surname
        if show_surname:
            try:
                user_data["surname"] = u.surname
            except Exception:
                user_data["surname"] = "[Error decrypting]"
        else:
            user_data["surname"] = "[Hidden]"
        
        ## Forename
        if show_forename:
            try:
                user_data["forename"] = u.forename
            except Exception:
                user_data["forename"] = "[Error decrypting]"
        else:
            user_data["forename"] = "[Hidden]"
        
        ## DOB
        if show_dob:
            try:
                user_data["dob"] = u.dob
            except Exception:
                user_data["dob"] = "[Error decrypting]"
        else:
            user_data["dob"] = "[Hidden]"
        
        ## Country
        if show_country:
            try:
                user_data["country"] = u.country
            except Exception:
                user_data["country"] = "[Error decrypting]"
        else:
            user_data["country"] = "[Hidden]"
            
        ## Email
        if show_email:
            try:
                user_data["email"] = u.email
            except Exception:
                user_data["email"] = "[Error decrypting]"
        else:
            user_data["email"] = "[Hidden]"

        users_list.append(user_data)

    return render_template("users.html", users=users_list, show_email=show_email)



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/")
def home():
    return render_template(
        "home.html",
        logged_in=session.get("logged_in", False),
        username=session.get("username"),
        profile_pic=session.get("profile_pic"),
    )


# ------------------- Database Initialization -------------------

def initialize_db():
    with app.app_context():
        # Ensure DB file exists
        if not os.path.exists(DB_FILE):
            open(DB_FILE, 'a').close()

        # Check missing tables
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        required_tables = [t.name for t in db.metadata.sorted_tables]
        missing_tables = [t for t in required_tables if not inspector.has_table(t)]
        if missing_tables:
            db.create_all()
            print(f"Created missing tables: {missing_tables}")

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
