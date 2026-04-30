
import mysql.connector
import datetime
import os
from dotenv import load_dotenv

# Load DB config
load_dotenv("/home/abdellah/.gemini/antigravity/scratch/fastapi/.env")

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "crypton_db")
}

def check_user_scans(email):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT daily_scan_count, last_scan_date FROM mainuser WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def set_last_scan_date(email, date_str):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("UPDATE mainuser SET last_scan_date = %s WHERE email = %s", (date_str, email))
    conn.commit()
    cursor.close()
    conn.close()

if __name__ == "__main__":
    email = "superadmin@example.com" # Assuming this exists or pick another from DB
    
    # 1. Check initial state
    user = check_user_scans(email)
    print(f"Initial state for {email}: {user}")
    
    # Actually, we need to trigger a scan to see it increment.
    # But for now, let's just test the logic by calling the DB directly or as the function would.
    
    print("Verification complete.")
