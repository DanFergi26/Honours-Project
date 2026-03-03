# services/role_service.py

from models.models import db, Roles, Permissions, RolePermissions, User

def create_permission(name, desc):
    existing = Permissions.query.filter_by(permName=name).first()
    if existing:
        return "Permission already exists."

    db.session.add(Permissions(permName=name, permDesc=desc))
    db.session.commit()
    return None


def create_role(name, desc):
    existing = Roles.query.filter_by(roleName=name).first()
    if existing:
        return "Role already exists."

    db.session.add(Roles(roleName=name, roleDesc=desc))
    db.session.commit()
    return None


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

    db.session.add(RolePermissions(roleID=role.id, permissionsID=perm.id))
    db.session.commit()

    return None


def assign_role_to_user(username, role_id):
    user = User.query.filter_by(username=username).first()
    role = Roles.query.get(role_id)

    if not user:
        return "User not found."
    if not role:
        return "Role not found."

    user.roleID = role.id
    db.session.commit()

    return None