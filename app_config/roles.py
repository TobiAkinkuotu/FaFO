# Define Role-Based Access Control (RBAC) permissions

ROLES = {
    "admin": {
        "can_submit": True,
        "can_review": True,
        "can_manage_users": False,
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

VALID_ROLES = list(ROLES.keys())

ROLE_DESCRIPTIONS = {
    "admin": "Review system status and oversee workflows.",
    "reviewer": "Review incidents, assess evidence, and export audit-ready reports.",
    "submitter": "Submit incidents, attach evidence, and track your reports.",
    "lawyer": "Review legal cases and access relevant incident summaries.",
}
