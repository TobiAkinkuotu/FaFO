import streamlit as st

ROLE_PAGES = {
    "submitter": ["Submit Incident", "My Incidents", "Upload Evidence", "Settings"],
    "reviewer": ["Dashboard", "Submit Incident", "Evidence Repository", "Search & Export", "Settings"],
    "admin": ["Dashboard", "Submit Incident", "Evidence Repository", "Search & Export", "Settings", "Admin Panel"],
    "lawyer": ["Lawyer Portal", "Settings"],
}

PAGE_ROLE_MATRIX = {
    "Dashboard": ["reviewer", "admin"],
    "Submit Incident": ["submitter", "reviewer", "admin"],
    "My Incidents": ["submitter"],
    "Upload Evidence": ["submitter"],
    "Evidence Repository": ["reviewer", "admin"],
    "Search & Export": ["reviewer", "admin"],
    "Admin Panel": ["admin"],
    "Lawyer Portal": ["lawyer"],
    "Settings": ["submitter", "reviewer", "admin", "lawyer"],
}

DEFAULT_PAGE = "Settings"


def normalize_role(role: str) -> str:
    return str(role or "").strip().lower()


def get_pages_for_role(role: str) -> list[str]:
    return ROLE_PAGES.get(normalize_role(role), [DEFAULT_PAGE])


def can_access_page(role: str, page: str) -> bool:
    normalized_role = normalize_role(role)
    if not normalized_role:
        return False
    allowed_roles = PAGE_ROLE_MATRIX.get(page)
    if allowed_roles is None:
        return False
    return normalized_role in allowed_roles


def abort_if_unauthorized(page: str, role: str):
    if not can_access_page(role, page):
        st.error(f"Unauthorized access: {page} is not allowed for role '{normalize_role(role) or 'unknown'}'.")
        st.stop()
