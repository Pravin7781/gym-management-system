import os
import sqlite3
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash

# Path to the SQLite database file (supports optional Render persistent disk via DATABASE_PATH)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'gym.db'))
os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)


def get_db_connection():
    """
    Establishes and returns a connection to the SQLite database.
    Configures row_factory to sqlite3.Row for dictionary-like column access
    and enables foreign key enforcement.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Initializes the SQLite database with required tables, constraints, and indexes.
    Persists existing tables without dropping them and seeds initial sample records
    if tables are empty.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table (Admin Authentication)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL
        );
    """)

    # 2. Membership Plans Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS membership_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_name TEXT UNIQUE NOT NULL,
            duration_days INTEGER NOT NULL,
            price REAL NOT NULL,
            description TEXT
        );
    """)

    # 3. Members Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            age INTEGER NOT NULL,
            gender TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT NOT NULL,
            address TEXT,
            registration_date TEXT NOT NULL,
            plan_id INTEGER NOT NULL,
            start_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            FOREIGN KEY (plan_id) REFERENCES membership_plans(id) ON DELETE RESTRICT
        );
    """)

    # 4. Trainers Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trainers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trainer_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            specialization TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT NOT NULL,
            experience INTEGER NOT NULL,
            salary REAL NOT NULL,
            availability TEXT NOT NULL
        );
    """)

    # 5. Payments Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id TEXT UNIQUE NOT NULL,
            member_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            payment_method TEXT NOT NULL,
            payment_date TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE
        );
    """)

    # 6. Attendance Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL,
            attendance_date TEXT NOT NULL,
            check_in_time TEXT NOT NULL,
            check_out_time TEXT,
            FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE,
            UNIQUE(member_id, attendance_date)
        );
    """)

    # Ensure check_out_time column exists for backward compatibility
    try:
        cursor.execute("ALTER TABLE attendance ADD COLUMN check_out_time TEXT;")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Create Indexes for Query Optimization
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_members_member_id ON members(member_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_members_expiry ON members(expiry_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_members_plan_id ON members(plan_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(payment_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_member_id ON payments(member_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(attendance_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_member_id ON attendance(member_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_trainers_trainer_id ON trainers(trainer_id);")

    conn.commit()

    # Seed initial data if tables are empty
    seed_initial_data(conn)
    conn.close()


def seed_initial_data(conn):
    """
    Seeds initial realistic sample records into the database if empty.
    Preserves existing data if already present.
    """
    cursor = conn.cursor()
    today = date.today()
    today_str = today.isoformat()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Seed Admin User if users table is empty
    cursor.execute("SELECT COUNT(*) FROM users;")
    if cursor.fetchone()[0] == 0:
        admin_password_hash = generate_password_hash("password123")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?);",
            ("admin", admin_password_hash, "admin", now_str)
        )

    # Seed Membership Plans if empty
    cursor.execute("SELECT COUNT(*) FROM membership_plans;")
    if cursor.fetchone()[0] == 0:
        default_plans = [
            ("Monthly Basic", 30, 1500.00, "Full gym floor access with standard locker access."),
            ("Quarterly Standard", 90, 4000.00, "Gym access, cardio zone, and 1 complimentary trainer assessment."),
            ("Half-Yearly Pro", 180, 7500.00, "All gym areas, free group fitness sessions, sauna access."),
            ("Annual Elite", 365, 14000.00, "VIP all-inclusive access, guest privileges, locker reservation, custom nutrition plan.")
        ]
        cursor.executemany(
            "INSERT INTO membership_plans (plan_name, duration_days, price, description) VALUES (?, ?, ?, ?);",
            default_plans
        )

    # Note: Members, Trainers, Payments, and Attendance are preserved as clean/user-managed data.
    conn.commit()


def clear_all_operational_data():
    """
    Clears all member registrations, attendance logs, payment transactions,
    and trainer records, providing a fresh, clean slate for custom data entry.
    Preserves the administrative user and configurable membership plans.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM attendance;")
    cursor.execute("DELETE FROM payments;")
    cursor.execute("DELETE FROM members;")
    cursor.execute("DELETE FROM trainers;")
    # Reset autoincrement sequence counters for clean IDs
    cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('members', 'payments', 'attendance', 'trainers');")
    conn.commit()
    conn.close()


def generate_next_member_id():
    """
    Generates a sequential, formatted Member ID (e.g., MEM-1009).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT member_id FROM members ORDER BY id DESC LIMIT 1;")
    last_row = cursor.fetchone()
    conn.close()

    if not last_row or not last_row["member_id"]:
        return "MEM-1001"

    last_id_str = last_row["member_id"]
    try:
        prefix, num_part = last_id_str.split("-")
        next_num = int(num_part) + 1
        return f"MEM-{next_num:04d}"
    except (ValueError, IndexError):
        return f"MEM-{datetime.now().strftime('%M%S')}"


def generate_next_trainer_id():
    """
    Generates a sequential, formatted Trainer ID (e.g., TRN-2005).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT trainer_id FROM trainers ORDER BY id DESC LIMIT 1;")
    last_row = cursor.fetchone()
    conn.close()

    if not last_row or not last_row["trainer_id"]:
        return "TRN-2001"

    last_id_str = last_row["trainer_id"]
    try:
        prefix, num_part = last_id_str.split("-")
        next_num = int(num_part) + 1
        return f"TRN-{next_num:04d}"
    except (ValueError, IndexError):
        return f"TRN-{datetime.now().strftime('%M%S')}"


def generate_next_payment_id():
    """
    Generates a sequential, formatted Payment ID (e.g., PAY-3009).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT payment_id FROM payments ORDER BY id DESC LIMIT 1;")
    last_row = cursor.fetchone()
    conn.close()

    if not last_row or not last_row["payment_id"]:
        return "PAY-3001"

    last_id_str = last_row["payment_id"]
    try:
        prefix, num_part = last_id_str.split("-")
        next_num = int(num_part) + 1
        return f"PAY-{next_num:04d}"
    except (ValueError, IndexError):
        return f"PAY-{datetime.now().strftime('%M%S')}"


def calculate_expiry_date(start_date_str, duration_days):
    """
    Calculates the expiry date given a start date string (YYYY-MM-DD)
    and the duration in days.
    """
    try:
        start_dt = datetime.strptime(start_date_str, "%Y-%m-%d").date()
    except ValueError:
        start_dt = date.today()
    expiry_dt = start_dt + timedelta(days=int(duration_days))
    return expiry_dt.isoformat()


def get_member_status(expiry_date_str):
    """
    Determines if a membership is Active or Expired based on current date.
    Returns a tuple: (status: str, days_difference: int).
    Positive days_difference = days remaining.
    Negative days_difference = days since expired.
    """
    try:
        exp_dt = datetime.strptime(expiry_date_str, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return "Expired", 0

    today = date.today()
    diff = (exp_dt - today).days

    if diff >= 0:
        return "Active", diff
    else:
        return "Expired", diff
