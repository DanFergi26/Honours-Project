from models.models import db, Roles, Permissions, RolePermissions, User

# ------------------- CREATE PERMISSION -------------------
def create_permission(name, desc):
    existing = Permissions.query.filter_by(permName=name).first()
    if existing:
        return "Permission already exists."

    if not name or not desc:
        return "Permission name and description are required."

    name = name.strip()
    desc = desc.strip()

    if len(name) > 50:
        return "Permission name must be 50 characters or fewer."

    if len(desc) > 200:
        return "Permission description must be 200 characters or fewer."

    try:
        db.session.add(Permissions(
            permName=name,
            permDesc=desc
        ))
        db.session.commit()
        return None

    except Exception as e:
        db.session.rollback()
        return f"Error creating permission: {str(e)}"


# ------------------- CREATE ROLE -------------------
def create_role(name, desc):
    existing = Roles.query.filter_by(roleName=name).first()
    if existing:
        return "Role already exists."

    if not name or not desc:
        return "Role name and description are required."

    name = name.strip()
    desc = desc.strip()

    if len(name) > 50:
        return "Role name must be 50 characters or fewer."

    if len(desc) > 200:
        return "Role description must be 200 characters or fewer."

    try:
        db.session.add(Roles(
            roleName=name,
            roleDesc=desc
        ))
        db.session.commit()
        return None

    except Exception as e:
        db.session.rollback()
        return f"Error creating role: {str(e)}"


# ------------------- ASSIGN PERMISSION TO ROLE -------------------
def assign_permission_to_role(role_name, perm_name):
    role = Roles.query.filter_by(roleName=role_name).first()
    perm = Permissions.query.filter_by(permName=perm_name).first()

    if not role:
        return f"Role '{role_name}' does not exist."
    if not perm:
        return f"Permission '{perm_name}' does not exist."

    existing = RolePermissions.query.filter_by(
        roleID=role.id,
        permissionsID=perm.id
    ).first()

    if existing:
        return "Permission already assigned."

    try:
        db.session.add(RolePermissions(
            roleID=role.id,
            permissionsID=perm.id
        ))
        db.session.commit()
        return None

    except Exception as e:
        db.session.rollback()
        return f"Error assigning permission: {str(e)}"


# ------------------- ASSIGN ROLE TO USER -------------------
def assign_role_to_user(username, role_id):
    user = User.query.filter_by(username=username).first()
    role = Roles.query.get(role_id)

    if not user:
        return "User not found."
    if not role:
        return "Role not found."

    try:
        user.roleID = role.id
        db.session.commit()
        return None

    except Exception as e:
        db.session.rollback()
        return f"Error assigning role: {str(e)}"