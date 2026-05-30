import sqlite3
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from app_config.settings import DATABASE_PATH
from modules.auth import get_password_hash

def seed_admin():
    print("Seeding default admin user...")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Check if admin already exists
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if cursor.fetchone() is None:
        hashed_pw = get_password_hash("admin123")
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, email)
            VALUES (?, ?, ?, ?)
        """, ("admin", hashed_pw, "admin", "admin@fafo.local"))
        conn.commit()
        print("Admin user created: admin / admin123")
    else:
        print("Admin user already exists.")
        
    conn.close()

if __name__ == "__main__":
    seed_admin()
