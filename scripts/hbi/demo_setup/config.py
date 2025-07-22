"""
Configuration for the RBAC Demo Scenario Setup
"""

# --- API and Setup Configuration ---
API_TIMEOUT = 60
MAX_RETRIES = 3
MAX_WORKERS = 10
REQUIRED_HOSTS = 100

# --- Demo Specification ---
DEMO_USERS = {
    "jdoe": {"user_id": "12345", "is_admin": True},
    "sara": {"user_id": "54321", "is_admin": False},
    "alice": {"user_id": "11111", "is_admin": False},
    "bob": {"user_id": "22222", "is_admin": False},
}

DEMO_WORKSPACES = ["IT Team A", "IT Team B"]

INVENTORY_PERMISSIONS = [
    "inventory:hosts:read",
    "inventory:hosts:write",
    "inventory:groups:read",
    "inventory:groups:write",
]

STALENESS_PERMISSIONS = [
    "staleness:staleness:read",
]
