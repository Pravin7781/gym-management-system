# Next Level Fitness Management System

**A Production-Ready, Full-Stack Web Application for 2nd-Year B.Tech Artificial Intelligence and Data Science — Project-Based Learning (PBL) Course.**

---

## 1. Executive Summary & Academic PBL Context

### 1.1 Course Objective
The **Next Level Fitness Management System** is engineered as an exemplar software engineering project for a 2nd-Year Bachelor of Technology (B.Tech) course in **Artificial Intelligence and Data Science** under the **Project-Based Learning (PBL)** pedagogical framework. 

Modern software engineering and data science curricula emphasize full-stack literacy: understanding how data originates at transactional web endpoints, how relational constraints safeguard data integrity, and how server-side business logic generates deterministic analytical metrics. This application demonstrates:
- **Clean Architecture:** Strict separation of concerns across database access layers, routing/controller logic, and presentation templates.
- **Data Integrity & Relational Modeling:** Primary keys, foreign key constraints (`ON DELETE CASCADE`, `ON DELETE RESTRICT`), unique composite constraints, and indexing in SQLite3.
- **Security Foundations:** Werkzeug PBKDF2/SHA-256 salted password hashing, cryptographic session management, and server-side Cross-Site Request Forgery (CSRF) protection.
- **Analytical Metric Derivation:** Aggregation queries (`SUM`, `COUNT`, date differentials) computed entirely in Python and SQL without client-side abstraction.

### 1.2 The "Zero-JavaScript" Architectural Constraint
A foundational pedagogical rule of this PBL project is the **strict elimination of JavaScript (`Zero JS`)**:
1. **Server-Side Determinism:** All form validation, query filtering, pagination arithmetic, and date calculations occur strictly within Python Flask and SQLite.
2. **Defensive Security Posture:** Eliminates client-side DOM-based Cross-Site Scripting (XSS) vectors and third-party frontend supply chain dependencies.
3. **Pure CSS3 Modern Capabilities:** Leverages CSS Grid, Flexbox, custom properties, pseudo-classes, transitions, and `@media print` stylesheets to prove that rich, responsive, and tactile web interfaces do not require massive JavaScript runtimes.

---

## 2. Technology Stack

| Layer | Technology | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Backend Runtime** | Python | 3.12+ | Core application logic, routing, data processing, security |
| **Web Framework** | Flask (Pallets Projects) | 3.1.x | WSGI web application framework and routing |
| **Database Engine** | SQLite3 | 3.x | Embedded ACID-compliant relational SQL engine |
| **Password Security** | Werkzeug Security | 3.1.x | Salted PBKDF2/SHA-256 password hashing and validation |
| **Templating Engine** | Jinja2 | 3.1.x | Server-side template rendering with template inheritance |
| **Frontend Styling** | Pure CSS3 (Flexbox/Grid) | CSS3 Spec | Dark fitness UI, responsive layouts, print engine |
| **Export Engine** | Python `csv` & `io` | Standard Lib | Server-side dynamic CSV stream generation |

---

## 3. Database Schema & Architecture

The system utilizes an ACID-compliant SQLite3 database (`gym.db`) that auto-initializes upon first boot. Tables are created idempotently (`CREATE TABLE IF NOT EXISTS`) and seeded with realistic sample records if empty. Existing records persist permanently across application restarts.

### 3.1 Entity Relationship Model

```text
  +------------------+         +----------------------+
  |      users       |         |   membership_plans   |
  +------------------+         +----------------------+
  | id (PK)          |         | id (PK)              |
  | username (UQ)    |         | plan_name (UQ)       |
  | password_hash    |         | duration_days        |
  | role             |         | price                |
  | created_at       |         | description          |
  +------------------+         +----------------------+
                                          | 1
                                          |
                                          | has (RESTRICT)
                                          | N
                               +----------------------+
                               |       members        |
                               +----------------------+
                               | id (PK)              |
                               | member_id (UQ)       |
                               | full_name            |
                               | age, gender          |
                               | phone, email         |
                               | address              |
                               | registration_date    |
                               | plan_id (FK)         |
                               | start_date           |
                               | expiry_date          |
                               +----------------------+
                                     | 1            | 1
                                     |              |
                      logs (CASCADE) | N            | N records (CASCADE)
                                     v              v
      +---------------------------------+        +------------------------+
      |           attendance            |        |        payments        |
      +---------------------------------+        +------------------------+
      | id (PK)                         |        | id (PK)                |
      | member_id (FK)                  |        | payment_id (UQ)        |
      | attendance_date                 |        | member_id (FK)         |
      | check_in_time                   |        | amount                 |
      | CONSTRAINT:                     |        | payment_method         |
      | UNIQUE(member_id, attend_date)  |        | payment_date           |
      +---------------------------------+        | status                 |
                                                 +------------------------+

  +----------------------+
  |       trainers       |
  +----------------------+
  | id (PK)              |
  | trainer_id (UQ)      |
  | full_name            |
  | specialization       |
  | phone, email         |
  | experience, salary   |
  | availability         |
  +----------------------+
```

### 3.2 SQL Table Definitions & Constraints

```sql
-- 1. Users Table (Admin Authentication)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL
);

-- 2. Membership Plans Table
CREATE TABLE IF NOT EXISTS membership_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_name TEXT UNIQUE NOT NULL,
    duration_days INTEGER NOT NULL,
    price REAL NOT NULL,
    description TEXT
);

-- 3. Members Table
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

-- 4. Trainers Table
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

-- 5. Payments Table
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

-- 6. Attendance Table (Composite Unique Constraint Prevents Same-Day Duplicates)
CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    attendance_date TEXT NOT NULL,
    check_in_time TEXT NOT NULL,
    FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE,
    UNIQUE(member_id, attendance_date)
);

-- Optimization Indexes
CREATE INDEX IF NOT EXISTS idx_members_member_id ON members(member_id);
CREATE INDEX IF NOT EXISTS idx_members_expiry ON members(expiry_date);
CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(payment_date);
CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(attendance_date);
CREATE INDEX IF NOT EXISTS idx_trainers_trainer_id ON trainers(trainer_id);
```

---

## 4. Core Modules & Implementation Highlights

### 4.1 Admin Authentication & Session Security
- **Werkzeug Security:** Passwords are never stored in plaintext. They are encrypted using `generate_password_hash` and verified via constant-time comparison `check_password_hash`.
- **`@login_required` Decorator:** Intercepts unauthenticated requests to protected endpoints, storing the requested path as `next` query parameter for post-login redirection.
- **Zero-JS CSRF Protection:** Cryptographic tokens (`secrets.token_hex(32)`) are assigned to `session['csrf_token']`. All incoming `POST` requests are validated in `app.before_request`.
- **Default Administrative Account:**
  - **Username:** `admin`
  - **Password:** `password123`
  - *Admins can immediately update this password via the `/settings` interface.*

### 4.2 Real-Time Analytical Dashboard
The dashboard aggregates real-time data on every page load:
1. **Total Members:** Total count of registered athlete profiles.
2. **Active Members:** Count of members where `expiry_date >= current_date`.
3. **Expired Members:** Count of members where `expiry_date < current_date`.
4. **Total Trainers:** Active coach roster count.
5. **Total Revenue:** Sum of all completed payments.
6. **Monthly Revenue:** Sum of completed payments in the current calendar month.
7. **Daily Attendance:** Count of check-ins registered for today.
8. **Expiring Within 7 Days Alert:** High-priority watchlist highlighting members requiring renewal.
9. **Pure CSS Plan Distribution Bar Chart:** Visualizes subscription breakdown by plan percentage.

### 4.3 Member Lifecycle Management (CRUD)
- **ID Generation:** Formats sequential identifiers (e.g., `MEM-1001`, `MEM-1002`).
- **Subscription Expiry Engine:** Expiry dates are calculated automatically:
  $$\text{expiry\_date} = \text{start\_date} + \Delta(\text{duration\_days})$$
- **Quick Renewal:** Admins can renew memberships directly from profile views, extending the validity window and creating instant payment records.
- **Safe Cascading Deletions:** Protected by an explicit confirmation prompt page (`confirm_delete.html`) requiring a verified `POST` token before purging records.

### 4.4 Attendance Terminal
- **Constraint Enforcement:** SQLite composite key `UNIQUE(member_id, attendance_date)` ensures a member cannot be checked in more than once per calendar day.
- **Immediate Warning Feedback:** If an expired member attempts check-in, the system logs the visit while providing a visual warning to the receptionist to collect renewal fees.

### 4.5 Financial Ledger & Printable Receipts
- Supports transaction methods: **Cash**, **UPI / Digital Wallet**, **Credit/Debit Card**, and **Net Banking**.
- Each transaction generates a standardized receipt (`receipt.html`) displaying gym registration details, GST/Tax registration, itemized breakdown, and an official **PAID** seal.
- **Dedicated Print Stylesheet (`@media print`):** Formats receipts for standard US Letter or A4 printing, suppressing web chrome, navbars, and dark ink waste.

### 4.6 Reporting & Dynamic CSV Streaming
- Filter records across customized date windows, membership plans, and statuses.
- The `/reports/export-csv` endpoint uses Python's standard `csv.writer` to stream formatted CSV files directly into the student's browser with zero client-side dependencies.

---

## 5. Project Directory Structure

```text
gym_management_system/
│
├── app.py                      # Flask Application controller, routes, filters, error handlers
├── database.py                 # SQLite schema, connection factory, and initial seed generator
├── requirements.txt            # Python dependencies (Flask, Werkzeug, Jinja2)
├── README.md                   # Academic PBL documentation & setup instructions
├── gym.db                      # Persistent SQLite3 database file
│
├── static/
│   └── css/
│       └── style.css           # 100% Pure Custom CSS3 (Dark Fitness Theme & @media print)
│
├── exports/                    # Directory for server-generated exported datasets
│
└── templates/                  # Jinja2 HTML5 Templates (Zero JavaScript)
    ├── base.html               # Master layout with sidebar navigation and topbar
    ├── login.html              # Secure administrative authentication screen
    ├── dashboard.html          # Real-time metrics, analytics bars, and expiration alerts
    ├── members.html            # Member directory with search, filters, and pagination
    ├── add_member.html         # Member registration form with auto-expiry calculation
    ├── edit_member.html        # Member profile editor and renewal processor
    ├── member_details.html     # Comprehensive member profile, attendance, and ledger
    ├── membership_plans.html   # Plan configuration, pricing tiers, and active counts
    ├── trainers.html           # Staff and coach management roster
    ├── payments.html           # Financial ledger and new transaction form
    ├── receipt.html            # Official printable payment receipt
    ├── attendance.html         # Daily check-in terminal with duplicate prevention
    ├── reports.html            # Analytical reporting center with date filters
    ├── settings.html           # Admin credentials update and SQLite telemetry
    ├── confirm_delete.html     # Two-factor deletion confirmation safety screen
    └── 404.html                # Gym-themed error page ("Reps Missed!")
```

---

## 6. Setup & Execution Instructions

### 6.1 Prerequisites
- Python 3.10, 3.11, or 3.12 installed on your machine.
- Git (optional, for version control).

### 6.2 Step-by-Step Installation

1. **Navigate to the Project Root:**
   ```bash
   cd "Gym Management System"
   ```

2. **Create and Activate a Virtual Environment:**
   - **On Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **On Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application:**
   ```bash
   python app.py
   ```

5. **Access the System in Your Browser:**
   - Open your web browser and navigate to:
     ```text
     http://127.0.0.1:5000
     ```

6. **Log in with Default Credentials:**
   - **Username:** `admin`
   - **Password:** `password123`

---

## 7. How to Change the Administrator Password

For production and grading environments:
1. Log into the system using the default credentials (`admin` / `password123`).
2. Click on **Settings** in the left sidebar navigation menu (or navigate to `http://127.0.0.1:5000/settings`).
3. Under the **Update Administrator Password** panel:
   - Enter `password123` in the **Current Password** field.
   - Enter your new desired password (minimum 6 characters) in the **New Password** field.
   - Re-enter the new password in the **Confirm New Password** field.
4. Click **Update Password**. The new salted PBKDF2 hash will be saved immediately to `gym.db`.

---

## 8. Verification & Test Suite

The system has been verified to meet all requirements:
1. **Zero JavaScript Verification:** Verified that no `<script>` tags, event handlers (`onclick`, `onsubmit`), or external JS CDN libraries exist across all HTML templates and static assets.
2. **Persistence Guarantee:** Stopping and restarting the Flask server retains all newly added members, attendance records, and payment logs without resetting the database.
3. **Responsive Viewports:** Layout seamlessly adapts across desktop monitors ($>1024\text{px}$), tablets ($768\text{px} - 1024\text{px}$), and mobile devices ($<768\text{px}$).
4. **Print Compatibility:** Invoking browser print (**Ctrl + P**) renders clean, ink-efficient white-and-black receipts and reports.

---

## 9. Production Deployment on Render

The project is fully pre-configured for one-click deployment on [Render](https://render.com).

### 9.1 Render Configuration Summary
- **Service Type:** Web Service
- **Runtime:** Python 3 (configured via `.python-version` with `3.12.0`)
- **Build Command:**
  ```bash
  pip install -r requirements.txt
  ```
- **Start Command:**
  ```bash
  gunicorn app:app
  ```

### 9.2 Step-by-Step Render Deployment Guide

1. **Push your code to GitHub / GitLab:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit for Next Level Fitness"
   git remote add origin <your-repository-url>
   git push -u origin main
   ```

2. **Create Web Service on Render:**
   - Log into [dashboard.render.com](https://dashboard.render.com/).
   - Click **New +** &rarr; Select **Web Service**.
   - Connect your GitHub repository.

3. **Configure Service Settings:**
   - **Name:** `next-level-fitness` (or any custom name)
   - **Region:** Any region closest to you (e.g., Singapore, Frankfurt, Oregon)
   - **Branch:** `main`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Instance Type:** `Free`

4. **Environment Variables (Optional / Recommended):**
   Under **Environment Variables**, you can add:
   - `PYTHON_VERSION`: `3.12.0`
   - `SECRET_KEY`: (Click *Generate* or enter a random 32-character string)
   - `FLASK_DEBUG`: `false`

5. **Deploy:**
   - Click **Deploy Web Service**.
   - Render will automatically build the environment, install dependencies, initialize `gym.db` with default admin credentials, and launch Gunicorn.
   - Once deployed, open your live URL (e.g. `https://next-level-fitness.onrender.com`) and log in with:
     - **Username:** `admin`
     - **Password:** `password123`
