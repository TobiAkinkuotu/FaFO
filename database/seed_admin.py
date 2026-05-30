import sqlite3
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from app_config.settings import DATABASE_PATH
from modules.auth import get_password_hash

def seed_admin():
    print("Seeding default test users...")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    test_users = [
        ("admin", "admin123", "admin", "admin@fafo.local"),
        ("reviewer", "reviewer123", "reviewer", "reviewer@fafo.local"),
        ("lawyer", "lawyer123", "lawyer", "lawyer@fafo.local"),
        ("submitter", "submitter123", "submitter", "submitter@fafo.local"),
    ]
    
    for username, password, role, email in test_users:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is None:
            hashed_pw = get_password_hash(password)
            cursor.execute("""
                INSERT INTO users (username, password_hash, role, email)
                VALUES (?, ?, ?, ?)
            """, (username, hashed_pw, role, email))
            print(f"{role.capitalize()} user created: {username} / {password}")
        else:
            print(f"{role.capitalize()} user already exists: {username}")
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    seed_admin()
