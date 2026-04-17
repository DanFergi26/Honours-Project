from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from flask_bcrypt import Bcrypt
from datetime import datetime
import os

db = SQLAlchemy()
bcrypt = Bcrypt()

# ---------------- Encryption Setup ----------------

INSTANCE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

KEY_FILE = os.path.join(INSTANCE_DIR, "secret.key")

if not os.path.exists(KEY_FILE):
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(ENCRYPTION_KEY)

with open(KEY_FILE, "rb") as f:
    ENCRYPTION_KEY = f.read()
fernet = Fernet(ENCRYPTION_KEY)


# ---------------- USER MODEL ----------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)

    _surname = db.Column(db.LargeBinary, nullable=False)
    _forename = db.Column(db.LargeBinary, nullable=False)

    email = db.Column(db.String(255), unique=True, nullable=False)
    _email_enc = db.Column(db.LargeBinary, nullable=True)

    _dob = db.Column(db.LargeBinary, nullable=False)
    _country = db.Column(db.LargeBinary, nullable=False)
    _bio = db.Column(db.LargeBinary, nullable=True)

    password = db.Column(db.String(255), nullable=False)
    profile_pic = db.Column(db.String(255))

    email_code = db.Column(db.String(6))
    roleID = db.Column(db.Integer, db.ForeignKey("roles.id"))

    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime)

    # ---------------- Password ----------------

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    # ---------------- Encryption ----------------

    def encrypt(self, value):
        return fernet.encrypt(value.encode()) if value else None

    def decrypt(self, value):
        if not value:
            return None
        try:
            return fernet.decrypt(value).decode()
        except Exception as e:
            return f"[DECRYPT ERROR]"

    # ---------------- Encrypted Email (optional) ----------------

    @property
    def email_enc(self):
        return self._email_enc

    @email_enc.setter
    def email_enc(self, value):
        self._email_enc = self.encrypt(value)

    # ---------------- Encrypted fields ----------------

    @property
    def surname(self):
        return self.decrypt(self._surname)

    @surname.setter
    def surname(self, value):
        self._surname = self.encrypt(value)

    @property
    def forename(self):
        return self.decrypt(self._forename)

    @forename.setter
    def forename(self, value):
        self._forename = self.encrypt(value)

    @property
    def dob(self):
        return self.decrypt(self._dob)

    @dob.setter
    def dob(self, value):
        self._dob = self.encrypt(value)

    @property
    def country(self):
        return self.decrypt(self._country)

    @country.setter
    def country(self, value):
        self._country = self.encrypt(value)

    @property
    def bio(self):
        return self.decrypt(self._bio) if self._bio else None

    @bio.setter
    def bio(self, value):
        self._bio = self.encrypt(value) if value else None


# ---------------- LOGIN LOGS ----------------

class LoginLog(db.Model):
    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    username_attempted = db.Column(db.String(150))
    ip_address = db.Column(db.String(45))

    success = db.Column(db.Boolean, nullable=False)
    timed_out = db.Column(db.Boolean, default=False)

    attempt_time = db.Column(db.DateTime, default=datetime.utcnow)


# ---------------- ROLES ----------------

class Roles(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    roleName = db.Column(db.String(50), unique=True, nullable=False)
    roleDesc = db.Column(db.String(200), nullable=False)


class Permissions(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    permName = db.Column(db.String(50), unique=True, nullable=False)
    permDesc = db.Column(db.String(200), nullable=False)


class RolePermissions(db.Model):
    __tablename__ = "role_permissions"

    roleID = db.Column(db.Integer, db.ForeignKey("roles.id"), primary_key=True)
    permissionsID = db.Column(db.Integer, db.ForeignKey("permissions.id"), primary_key=True)


# ---------------- FIGURES ----------------

class Figures(db.Model):
    __tablename__ = "figures"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    desc = db.Column(db.String(1000), nullable=False)

    brandID = db.Column(db.Integer, db.ForeignKey("brand.id"))
    manufacturerID = db.Column(db.Integer, db.ForeignKey("manufacturer.id"))

    genre = db.Column(db.String(50))
    series = db.Column(db.String(50))

    releaseDate = db.Column(db.String(50))

    retailPrice = db.Column(db.Float)
    avgPrice = db.Column(db.Float)

    itemSize = db.Column(db.Float)
    itemWeight = db.Column(db.Float)

    images = db.relationship("FigureImages", backref="figure", lazy=True)
    links = db.Column(db.String(2000))
    
    brand = db.relationship("Brand", backref="figures")
    manufacturer = db.relationship("Manufacturer", backref="figures")

class FigureImages(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    figure_id = db.Column(db.Integer, db.ForeignKey("figures.id"), nullable=False)

    image_path = db.Column(db.String(255), nullable=False)
    
class Brand(db.Model):
    __tablename__ = "brand"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    desc = db.Column(db.String(1000))


class Manufacturer(db.Model):
    __tablename__ = "manufacturer"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    desc = db.Column(db.String(1000))

# ---------------- COLLECTIONS ----------------
   
class UserCollection(db.Model):
    __tablename__ = "user_collections"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    figure_id = db.Column(db.Integer, db.ForeignKey("figures.id"))
    
class SubCollection(db.Model):
    __tablename__ = "subcollections"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(150), nullable=False)
    image = db.Column(db.String(255))
    
class SubCollectionItem(db.Model):
    __tablename__ = "subcollection_items"

    id = db.Column(db.Integer, primary_key=True)

    subcollection_id = db.Column(
        db.Integer,
        db.ForeignKey("subcollections.id"),
        nullable=False
    )

    figure_id = db.Column(
        db.Integer,
        db.ForeignKey("figures.id"),
        nullable=False
    )