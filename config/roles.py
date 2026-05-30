# Define Role-Based Access Control (RBAC) permissions

ROLES = {
    "admin": {
        "can_submit": True,
        "can_review": True,
        "can_manage_users": True,
        "can_export": True,
        "can_view_audit_logs": True,
        "is_read_only": False,
    },
    "reviewer": {
        "can_submit": False,
        "can_review": True,
        "can_manage_users": False,
        "can_export": True,
        "can_view_audit_logs": False,
        "is_read_only": False,
    },
    "submitter": {
        "can_submit": True,
        "can_review": False,
        "can_manage_users": False,
        "can_export": False,
        "can_view_audit_logs": False,
        "is_read_only": False,
    },
    "lawyer": {
        "can_submit": False,
        "can_review": False,
        "can_manage_users": False,
        "can_export": True,  # Can export approved incidents
        "can_view_audit_logs": False,
        "is_read_only": True,
    }
}
