# models/models.py

from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from flask_bcrypt import Bcrypt
import os

db = SQLAlchemy()
bcrypt = Bcrypt()

# ------------------- Encryption Setup -------------------

INSTANCE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

KEY_FILE = os.path.join(INSTANCE_DIR, "secret.key")

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(ENCRYPTION_KEY)

fernet = Fernet(ENCRYPTION_KEY)


# ------------------- User Model -------------------

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

    email_code = db.Column(db.String(6), nullable=True)
    roleID = db.Column(db.Integer, db.ForeignKey('Roles.id'), nullable=True)

    # ------------------- Password -------------------

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    # ------------------- Encryption -------------------

    def encrypt(self, value):
        return fernet.encrypt(value.encode()) if value else None

    def decrypt(self, value):
        if not value:
            return None
        try:
            return fernet.decrypt(value).decode()
        except Exception:
            return "[Invalid or old data]"

    # ------------------- Properties -------------------

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
    def email(self):
        return self.decrypt(self._email)

    @email.setter
    def email(self, value):
        self._email = self.encrypt(value)

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


# ------------------- Roles & Permissions -------------------

class Roles(db.Model):
    __tablename__ = 'Roles'

    id = db.Column(db.Integer, primary_key=True)
    roleName = db.Column(db.String(20), unique=True, nullable=False)
    roleDesc = db.Column(db.String(200), unique=True, nullable=False)

    permissions = db.relationship(
        'Permissions',
        secondary='RolePermissions',
        back_populates='roles'
    )


class Permissions(db.Model):
    __tablename__ = 'Permissions'

    id = db.Column(db.Integer, primary_key=True)
    permName = db.Column(db.String(20), unique=True, nullable=False)
    permDesc = db.Column(db.String(100), unique=True, nullable=False)

    roles = db.relationship(
        'Roles',
        secondary='RolePermissions',
        back_populates='permissions'
    )


class RolePermissions(db.Model):
    __tablename__ = 'RolePermissions'

    roleID = db.Column(db.Integer, db.ForeignKey('Roles.id'), primary_key=True)
    permissionsID = db.Column(db.Integer, db.ForeignKey('Permissions.id'), primary_key=True)


# ------------------- Figures -------------------

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

    releaseDate = db.Column(db.String(50), nullable=False)

    retailPrice = db.Column(db.Integer, nullable=False)
    avgPrice = db.Column(db.Integer, nullable=False)

    itemSize = db.Column(db.Integer, nullable=False)
    itemWeight = db.Column(db.Integer, nullable=False)

    links = db.Column(db.String(2000), nullable=False)

    # Relationships
    brand = db.relationship("Brand", backref="figures")
    manufacturer = db.relationship("Manufacturer", backref="figures")

    collection = db.relationship(
        'Collection',
        secondary='FigureCollection',
        back_populates='figures'
    )


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


# ------------------- Collections -------------------

class Collection(db.Model):
    __tablename__ = 'Collection'

    id = db.Column(db.Integer, primary_key=True)

    worth = db.Column(db.Integer, nullable=False)

    userID = db.Column(db.Integer, db.ForeignKey('User.id'))

    figures = db.relationship(
        'Figures',
        secondary='FigureCollection',
        back_populates='collection'
    )


class FigureCollection(db.Model):
    __tablename__ = 'FigureCollection'

    figuresID = db.Column(db.Integer, db.ForeignKey('Figures.id'), primary_key=True)
    collectionID = db.Column(db.Integer, db.ForeignKey('Collection.id'), primary_key=True)