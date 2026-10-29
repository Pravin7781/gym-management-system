import os
import csv
import io
import math
import secrets
import sqlite3
import time
from datetime import datetime, date, timedelta
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    Response,
    make_response
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

import database

# Initialize Flask Application
app = Flask(__name__)
# Stable secret key fallback for production deployments behind Gunicorn
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'next-level-fitness-production-key-2026-secure')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Configure ProxyFix for reverse-proxy deployment (Render, AWS, Nginx)
# Accurately resolves client IP for rate limiting and handles HTTPS forwarding
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Initialize database and tables on startup (works with Flask dev server and Gunicorn)
database.init_db()

# Pre-computed dummy hash to prevent timing attacks during authentication
DUMMY_PASSWORD_HASH = generate_password_hash("constant_time_dummy_guard_pass_2026")

# In-memory rate limiting and brute force shield: {client_ip: {'attempts': int, 'lockout_until': float}}
LOGIN_ATTEMPTS = {}


# -------------------------------------------------------------------------
# HTTP DEFENSIVE SECURITY HEADERS
# -------------------------------------------------------------------------
@app.after_request
def apply_defensive_security_headers(response):
    """
    Applies production-grade HTTP security headers on all responses.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


# -------------------------------------------------------------------------
# CSRF PROTECTION (ZERO-JAVASCRIPT SERVER-SIDE VALIDATION)
# -------------------------------------------------------------------------
@app.before_request
def csrf_protect():
    """
    Generates a secure CSRF token in session if not present.
    For all POST requests, validates the submitted csrf_token form field.
    """
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

    if request.method == 'POST':
        submitted_token = request.form.get('csrf_token')
        expected_token = session.get('csrf_token')

        if not submitted_token or not expected_token or submitted_token != expected_token:
            flash("Security check failed: Invalid or expired CSRF token. Please try again.", "danger")
            # Redirect back to the referrer or login
            return redirect(request.referrer or url_for('dashboard'))


@app.context_processor
def inject_global_template_variables():
    """
    Injects global variables into all Jinja2 templates without JS.
    """
    return {
        'csrf_token': session.get('csrf_token', ''),
        'current_user': session.get('username'),
        'current_role': session.get('role'),
        'today_str': date.today().isoformat(),
        'current_year': date.today().year,
        'app_name': "NEXT LEVEL FITNESS"
    }


# -------------------------------------------------------------------------
# AUTHENTICATION DECORATOR
# -------------------------------------------------------------------------
def login_required(f):
    """
    Decorator to protect routes requiring admin authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Authentication required. Please log in to access this page.", "warning")
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------------------------
# AUTHENTICATION ROUTES
# -------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Hardened Admin Login Page.
    Features:
    - Brute-force rate limiting & 60s cooldown lock after 5 failed attempts
    - Constant-time password verification to prevent timing attacks
    - Session regeneration upon login to eliminate session fixation
    - Server-side CSRF validation
    """
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    client_ip = request.remote_addr or '127.0.0.1'
    current_time = time.time()
    ip_state = LOGIN_ATTEMPTS.setdefault(client_ip, {'attempts': 0, 'lockout_until': 0})

    # Enforce brute-force cooldown lockout
    if ip_state['lockout_until'] > current_time:
        remaining_sec = math.ceil(ip_state['lockout_until'] - current_time)
        flash(f"Security Lockout: Too many failed login attempts. Access is locked for {remaining_sec} second(s).", "danger")
        return render_template('login.html', username='', locked_out=True, remaining_sec=remaining_sec)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()[:50]
        password = request.form.get('password', '')[:128]

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template('login.html', username=username)

        conn = database.get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?;",
            (username,)
        ).fetchone()
        conn.close()

        # Timing attack mitigation: always execute check_password_hash even if user is None
        target_hash = user['password_hash'] if user else DUMMY_PASSWORD_HASH
        is_authenticated = user is not None and check_password_hash(target_hash, password)

        if is_authenticated:
            # Reset brute-force counter on successful authentication
            LOGIN_ATTEMPTS[client_ip] = {'attempts': 0, 'lockout_until': 0}

            # Regenerate session to prevent session fixation
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['csrf_token'] = secrets.token_hex(32)
            session.permanent = True

            flash(f"Welcome back, {user['username']}! Logged in securely.", "success")
            next_url = request.args.get('next')
            if next_url and next_url.startswith('/'):
                return redirect(next_url)
            return redirect(url_for('dashboard'))
        else:
            # Increment failed attempt count
            ip_state['attempts'] += 1
            if ip_state['attempts'] >= 5:
                ip_state['lockout_until'] = current_time + 60
                flash("Security Alert: 5 consecutive failed login attempts detected. System locked for 60 seconds.", "danger")
                return render_template('login.html', username=username, locked_out=True, remaining_sec=60)
            else:
                remaining_attempts = 5 - ip_state['attempts']
                flash(f"Invalid credentials. Please verify your username and password. ({remaining_attempts} attempt(s) remaining before security lockout)", "danger")
                return render_template('login.html', username=username)

    return render_template('login.html', locked_out=False, remaining_sec=0)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    Logs out the current admin user and clears session data.
    """
    session.clear()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('login'))


def calculate_duration(check_in_str, check_out_str):
    """
    Computes human-readable duration between check-in and check-out times.
    """
    if not check_out_str:
        return "Training in Gym"
    try:
        t1 = datetime.strptime(check_in_str, "%H:%M:%S")
        t2 = datetime.strptime(check_out_str, "%H:%M:%S")
        diff_minutes = max(0, int((t2 - t1).total_seconds() / 60))
        hours = diff_minutes // 60
        mins = diff_minutes % 60
        if hours > 0:
            return f"{hours}h {mins}m"
        return f"{mins}m"
    except (ValueError, TypeError):
        return "Completed"


# -------------------------------------------------------------------------
# ADMIN DASHBOARD ROUTE
# -------------------------------------------------------------------------
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Executive Admin Dashboard displaying key operational pillars:
    - Real-time membership retention & active metrics
    - Live facility floor with Check-In & instant Check-Out action
    - Financial settlement summary in Rupees (₹)
    - Upcoming subscription expirations watchlist
    """
    conn = database.get_db_connection()
    today_str = date.today().isoformat()
    current_month_prefix = date.today().strftime('%Y-%m') + '%'
    seven_days_later_str = (date.today() + timedelta(days=7)).isoformat()

    # 1. Total Members
    total_members = conn.execute("SELECT COUNT(*) FROM members;").fetchone()[0]

    # 2. Active Members (expiry_date >= today)
    active_members = conn.execute(
        "SELECT COUNT(*) FROM members WHERE expiry_date >= ?;",
        (today_str,)
    ).fetchone()[0]

    # 3. Expired Members (expiry_date < today)
    expired_members = conn.execute(
        "SELECT COUNT(*) FROM members WHERE expiry_date < ?;",
        (today_str,)
    ).fetchone()[0]

    # 4. Total Trainers
    total_trainers = conn.execute("SELECT COUNT(*) FROM trainers;").fetchone()[0]

    # 5. Total Revenue (all completed payments)
    total_rev_row = conn.execute(
        "SELECT COALESCE(SUM(amount), 0.0) FROM payments WHERE status = 'Completed';"
    ).fetchone()
    total_revenue = round(total_rev_row[0], 2)

    # 6. Monthly Revenue (completed payments in current month)
    monthly_rev_row = conn.execute(
        "SELECT COALESCE(SUM(amount), 0.0) FROM payments WHERE status = 'Completed' AND payment_date LIKE ?;",
        (current_month_prefix,)
    ).fetchone()
    monthly_revenue = round(monthly_rev_row[0], 2)

    # 7. Today's Attendance & Live Gym Floor (with Check-Out status)
    floor_rows = conn.execute("""
        SELECT a.id as attendance_id, a.attendance_date, a.check_in_time, a.check_out_time,
               m.id as member_id, m.member_id as member_code, m.full_name, m.phone, p.plan_name
        FROM attendance a
        JOIN members m ON a.member_id = m.id
        JOIN membership_plans p ON m.plan_id = p.id
        WHERE a.attendance_date = ?
        ORDER BY (a.check_out_time IS NOT NULL), a.check_in_time DESC;
    """, (today_str,)).fetchall()

    today_attendance = len(floor_rows)
    live_floor_members = []
    currently_in_gym_count = 0

    for att in floor_rows:
        is_in_gym = not att['check_out_time']
        if is_in_gym:
            currently_in_gym_count += 1
        dur = calculate_duration(att['check_in_time'], att['check_out_time'])
        live_floor_members.append({
            'attendance_id': att['attendance_id'],
            'member_id': att['member_id'],
            'member_code': att['member_code'],
            'full_name': att['full_name'],
            'phone': att['phone'],
            'plan_name': att['plan_name'],
            'check_in_time': att['check_in_time'],
            'check_out_time': att['check_out_time'],
            'is_in_gym': is_in_gym,
            'duration': dur
        })

    # Available members who can check in right now (haven't checked in today)
    available_for_checkin = conn.execute("""
        SELECT m.id, m.member_id, m.full_name, p.plan_name, m.expiry_date
        FROM members m
        JOIN membership_plans p ON m.plan_id = p.id
        WHERE m.id NOT IN (
            SELECT member_id FROM attendance WHERE attendance_date = ?
        )
        ORDER BY m.full_name ASC;
    """, (today_str,)).fetchall()

    # Recent member registrations (last 5)
    recent_members_rows = conn.execute("""
        SELECT m.id, m.member_id, m.full_name, m.registration_date, m.start_date, m.expiry_date,
               p.plan_name, p.price
        FROM members m
        JOIN membership_plans p ON m.plan_id = p.id
        ORDER BY m.id DESC LIMIT 5;
    """).fetchall()

    recent_members = []
    for r in recent_members_rows:
        status, days_left = database.get_member_status(r['expiry_date'])
        recent_members.append({
            'id': r['id'],
            'member_id': r['member_id'],
            'full_name': r['full_name'],
            'registration_date': r['registration_date'],
            'plan_name': r['plan_name'],
            'expiry_date': r['expiry_date'],
            'status': status,
            'days_left': days_left
        })

    # Upcoming membership expirations (within next 7 days: today <= expiry_date <= today + 7 days)
    upcoming_exp_rows = conn.execute("""
        SELECT m.id, m.member_id, m.full_name, m.phone, m.expiry_date, p.plan_name
        FROM members m
        JOIN membership_plans p ON m.plan_id = p.id
        WHERE m.expiry_date >= ? AND m.expiry_date <= ?
        ORDER BY m.expiry_date ASC;
    """, (today_str, seven_days_later_str)).fetchall()

    upcoming_expirations = []
    for u in upcoming_exp_rows:
        _, days_left = database.get_member_status(u['expiry_date'])
        upcoming_expirations.append({
            'id': u['id'],
            'member_id': u['member_id'],
            'full_name': u['full_name'],
            'phone': u['phone'],
            'plan_name': u['plan_name'],
            'expiry_date': u['expiry_date'],
            'days_left': days_left
        })

    # Plan distribution metrics for pure CSS bar chart
    plan_distribution_rows = conn.execute("""
        SELECT p.plan_name, COUNT(m.id) as member_count
        FROM membership_plans p
        LEFT JOIN members m ON p.id = m.plan_id
        GROUP BY p.id, p.plan_name
        ORDER BY member_count DESC;
    """).fetchall()

    plan_stats = []
    for p_row in plan_distribution_rows:
        count = p_row['member_count']
        percentage = round((count / total_members * 100), 1) if total_members > 0 else 0
        plan_stats.append({
            'plan_name': p_row['plan_name'],
            'count': count,
            'percentage': percentage
        })

    # Active membership percentage for health meter
    active_percentage = round((active_members / total_members * 100), 1) if total_members > 0 else 0

    conn.close()

    return render_template(
        'dashboard.html',
        total_members=total_members,
        active_members=active_members,
        expired_members=expired_members,
        total_trainers=total_trainers,
        total_revenue=total_revenue,
        monthly_revenue=monthly_revenue,
        today_attendance=today_attendance,
        currently_in_gym_count=currently_in_gym_count,
        live_floor_members=live_floor_members,
        available_for_checkin=available_for_checkin,
        active_percentage=active_percentage,
        recent_members=recent_members,
        upcoming_expirations=upcoming_expirations,
        plan_stats=plan_stats
    )


@app.route('/attendance/<int:id>/checkout', methods=['POST'])
@login_required
def checkout_attendance(id):
    """
    Facility Floor Check-Out.
    Records checkout timestamp and computes workout duration.
    """
    conn = database.get_db_connection()
    att = conn.execute("""
        SELECT a.*, m.full_name, m.member_id as member_code
        FROM attendance a
        JOIN members m ON a.member_id = m.id
        WHERE a.id = ?;
    """, (id,)).fetchone()

    if not att:
        conn.close()
        flash("Attendance record not found.", "danger")
        return redirect(request.referrer or url_for('dashboard'))

    check_out_now = datetime.now().strftime("%H:%M:%S")
    conn.execute("UPDATE attendance SET check_out_time = ? WHERE id = ?;", (check_out_now, id))
    conn.commit()
    conn.close()

    duration = calculate_duration(att['check_in_time'], check_out_now)
    flash(f"Check-Out Recorded: {att['full_name']} ({att['member_code']}) checked out at {check_out_now} (Session duration: {duration}).", "success")
    return redirect(request.referrer or url_for('dashboard'))


# -------------------------------------------------------------------------
# MEMBER MANAGEMENT (CRUD)
# -------------------------------------------------------------------------
@app.route('/members')
@login_required
def members_list():
    """
    List members with server-side search, plan filter, status filter, and pagination.
    """
    search_query = request.args.get('q', '').strip()
    plan_filter = request.args.get('plan_id', '').strip()
    status_filter = request.args.get('status', 'all').strip()

    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
    per_page = 10

    conn = database.get_db_connection()
    today_str = date.today().isoformat()

    # Build SQL dynamically with parameterized queries
    query = """
        SELECT m.id, m.member_id, m.full_name, m.age, m.gender, m.phone, m.email,
               m.registration_date, m.plan_id, m.start_date, m.expiry_date,
               p.plan_name, p.price
        FROM members m
        JOIN membership_plans p ON m.plan_id = p.id
        WHERE 1=1
    """
    params = []

    # Search filter: matches member_id, full_name, phone, or email
    if search_query:
        query += " AND (m.member_id LIKE ? OR m.full_name LIKE ? OR m.phone LIKE ? OR m.email LIKE ?)"
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term, like_term, like_term])

    # Plan filter
    if plan_filter and plan_filter.isdigit():
        query += " AND m.plan_id = ?"
        params.append(int(plan_filter))

    # Status filter
    if status_filter == 'active':
        query += " AND m.expiry_date >= ?"
        params.append(today_str)
    elif status_filter == 'expired':
        query += " AND m.expiry_date < ?"
        params.append(today_str)

    # Order by ID descending
    query += " ORDER BY m.id DESC"

    all_matching_rows = conn.execute(query, params).fetchall()
    total_records = len(all_matching_rows)
    total_pages = max(1, math.ceil(total_records / per_page))

    # Paginate rows
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    paginated_rows = all_matching_rows[start_index:end_index]

    members = []
    for r in paginated_rows:
        status, days_left = database.get_member_status(r['expiry_date'])
        members.append({
            'id': r['id'],
            'member_id': r['member_id'],
            'full_name': r['full_name'],
            'age': r['age'],
            'gender': r['gender'],
            'phone': r['phone'],
            'email': r['email'],
            'registration_date': r['registration_date'],
            'plan_name': r['plan_name'],
            'price': r['price'],
            'start_date': r['start_date'],
            'expiry_date': r['expiry_date'],
            'status': status,
            'days_left': days_left
        })

    # Available plans for the filter dropdown
    plans = conn.execute("SELECT id, plan_name FROM membership_plans ORDER BY id ASC;").fetchall()
    conn.close()

    return render_template(
        'members.html',
        members=members,
        plans=plans,
        search_query=search_query,
        plan_filter=plan_filter,
        status_filter=status_filter,
        page=page,
        total_pages=total_pages,
        total_records=total_records,
        has_prev=(page > 1),
        has_next=(page < total_pages)
    )


@app.route('/members/add', methods=['GET', 'POST'])
@login_required
def add_member():
    """
    Registers a new gym member with auto-generated ID, automated expiry date,
    and optional initial payment recording.
    """
    conn = database.get_db_connection()
    plans = conn.execute("SELECT id, plan_name, duration_days, price FROM membership_plans ORDER BY id ASC;").fetchall()

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        age = request.form.get('age', '').strip()
        gender = request.form.get('gender', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        address = request.form.get('address', '').strip()
        plan_id = request.form.get('plan_id', '').strip()
        start_date = request.form.get('start_date', '').strip() or date.today().isoformat()
        record_payment = request.form.get('record_payment') == 'yes'
        payment_method = request.form.get('payment_method', 'Cash')

        # Server-side validation
        if not full_name or not age or not gender or not phone or not email or not plan_id:
            flash("Please fill in all required fields accurately.", "danger")
            conn.close()
            return render_template(
                'add_member.html',
                plans=plans,
                next_member_id=database.generate_next_member_id(),
                form_data=request.form
            )

        try:
            age_int = int(age)
            if age_int < 12 or age_int > 100:
                flash("Member age must be between 12 and 100.", "danger")
                conn.close()
                return render_template(
                    'add_member.html',
                    plans=plans,
                    next_member_id=database.generate_next_member_id(),
                    form_data=request.form
                )
        except ValueError:
            flash("Please enter a valid numeric age.", "danger")
            conn.close()
            return render_template(
                'add_member.html',
                plans=plans,
                next_member_id=database.generate_next_member_id(),
                form_data=request.form
            )

        # Lookup plan details for duration and pricing
        selected_plan = conn.execute(
            "SELECT * FROM membership_plans WHERE id = ?;",
            (int(plan_id),)
        ).fetchone()

        if not selected_plan:
            flash("Selected membership plan does not exist.", "danger")
            conn.close()
            return render_template(
                'add_member.html',
                plans=plans,
                next_member_id=database.generate_next_member_id(),
                form_data=request.form
            )

        # Calculate expiry date
        expiry_date = database.calculate_expiry_date(start_date, selected_plan['duration_days'])
        member_id = database.generate_next_member_id()
        reg_date = date.today().isoformat()

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO members (
                member_id, full_name, age, gender, phone, email, address,
                registration_date, plan_id, start_date, expiry_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            member_id, full_name, age_int, gender, phone, email, address,
            reg_date, int(plan_id), start_date, expiry_date
        ))
        new_member_row_id = cursor.lastrowid

        # Record initial payment if requested
        if record_payment:
            pay_id = database.generate_next_payment_id()
            cursor.execute("""
                INSERT INTO payments (
                    payment_id, member_id, amount, payment_method, payment_date, status
                ) VALUES (?, ?, ?, ?, ?, ?);
            """, (
                pay_id, new_member_row_id, selected_plan['price'],
                payment_method, start_date, "Completed"
            ))

        conn.commit()
        conn.close()

        flash(f"Member '{full_name}' ({member_id}) successfully registered!", "success")
        return redirect(url_for('member_details', id=new_member_row_id))

    next_member_id = database.generate_next_member_id()
    conn.close()
    return render_template('add_member.html', plans=plans, next_member_id=next_member_id, form_data={})


@app.route('/members/<int:id>')
@login_required
def member_details(id):
    """
    Displays full member profile, plan status, countdown, attendance history,
    and payment records.
    """
    conn = database.get_db_connection()
    member = conn.execute("""
        SELECT m.*, p.plan_name, p.duration_days, p.price, p.description as plan_description
        FROM members m
        JOIN membership_plans p ON m.plan_id = p.id
        WHERE m.id = ?;
    """, (id,)).fetchone()

    if not member:
        conn.close()
        flash("Member record not found.", "danger")
        return redirect(url_for('members_list'))

    status, days_left = database.get_member_status(member['expiry_date'])

    # Attendance history
    attendance_history = conn.execute("""
        SELECT * FROM attendance
        WHERE member_id = ?
        ORDER BY attendance_date DESC, check_in_time DESC
        LIMIT 20;
    """, (id,)).fetchall()

    # Total attendances count
    attendance_count = conn.execute(
        "SELECT COUNT(*) FROM attendance WHERE member_id = ?;",
        (id,)
    ).fetchone()[0]

    # Payment history
    payment_history = conn.execute("""
        SELECT * FROM payments
        WHERE member_id = ?
        ORDER BY payment_date DESC, id DESC;
    """, (id,)).fetchall()

    # Total amount paid
    total_paid_row = conn.execute(
        "SELECT COALESCE(SUM(amount), 0.0) FROM payments WHERE member_id = ? AND status = 'Completed';",
        (id,)
    ).fetchone()
    total_paid = round(total_paid_row[0], 2)

    # Check if attended today
    today_str = date.today().isoformat()
    attended_today = conn.execute(
        "SELECT 1 FROM attendance WHERE member_id = ? AND attendance_date = ?;",
        (id, today_str)
    ).fetchone() is not None

    conn.close()

    return render_template(
        'member_details.html',
        member=member,
        status=status,
        days_left=days_left,
        attendance_history=attendance_history,
        attendance_count=attendance_count,
        payment_history=payment_history,
        total_paid=total_paid,
        attended_today=attended_today
    )


@app.route('/members/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_member(id):
    """
    Edits member details, allows plan renewals or manual expiry date adjustments.
    """
    conn = database.get_db_connection()
    member = conn.execute("SELECT * FROM members WHERE id = ?;", (id,)).fetchone()

    if not member:
        conn.close()
        flash("Member record not found.", "danger")
        return redirect(url_for('members_list'))

    plans = conn.execute("SELECT id, plan_name, duration_days, price FROM membership_plans ORDER BY id ASC;").fetchall()

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        age = request.form.get('age', '').strip()
        gender = request.form.get('gender', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        address = request.form.get('address', '').strip()
        plan_id = request.form.get('plan_id', '').strip()
        start_date = request.form.get('start_date', '').strip()
        custom_expiry = request.form.get('expiry_date', '').strip()
        action_type = request.form.get('action_type', 'update')

        if not full_name or not age or not gender or not phone or not email or not plan_id:
            flash("All required fields must be filled out.", "danger")
            conn.close()
            return render_template('edit_member.html', member=member, plans=plans)

        try:
            age_int = int(age)
        except ValueError:
            flash("Age must be a valid number.", "danger")
            conn.close()
            return render_template('edit_member.html', member=member, plans=plans)

        selected_plan = conn.execute("SELECT * FROM membership_plans WHERE id = ?;", (int(plan_id),)).fetchone()
        if not selected_plan:
            flash("Invalid plan selected.", "danger")
            conn.close()
            return render_template('edit_member.html', member=member, plans=plans)

        # Handle Renewal Action
        if action_type == 'renew':
            # Renew extending from either current expiry or today (whichever is later)
            today = date.today()
            try:
                current_exp = datetime.strptime(member['expiry_date'], "%Y-%m-%d").date()
                base_date = max(today, current_exp)
            except ValueError:
                base_date = today

            new_expiry_date = (base_date + timedelta(days=selected_plan['duration_days'])).isoformat()
            new_start_date = base_date.isoformat()

            conn.execute("""
                UPDATE members
                SET plan_id = ?, start_date = ?, expiry_date = ?
                WHERE id = ?;
            """, (int(plan_id), new_start_date, new_expiry_date, id))

            # Auto create renewal payment record
            pay_id = database.generate_next_payment_id()
            conn.execute("""
                INSERT INTO payments (
                    payment_id, member_id, amount, payment_method, payment_date, status
                ) VALUES (?, ?, ?, ?, ?, ?);
            """, (pay_id, id, selected_plan['price'], "UPI", today.isoformat(), "Completed"))

            conn.commit()
            conn.close()

            flash(f"Membership successfully renewed for {selected_plan['duration_days']} days! Payment record created.", "success")
            return redirect(url_for('member_details', id=id))

        # Standard Update Action
        final_expiry = custom_expiry if custom_expiry else database.calculate_expiry_date(start_date, selected_plan['duration_days'])

        conn.execute("""
            UPDATE members
            SET full_name = ?, age = ?, gender = ?, phone = ?, email = ?,
                address = ?, plan_id = ?, start_date = ?, expiry_date = ?
            WHERE id = ?;
        """, (
            full_name, age_int, gender, phone, email, address,
            int(plan_id), start_date, final_expiry, id
        ))
        conn.commit()
        conn.close()

        flash(f"Member '{full_name}' updated successfully.", "success")
        return redirect(url_for('member_details', id=id))

    conn.close()
    return render_template('edit_member.html', member=member, plans=plans)


@app.route('/members/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete_member(id):
    """
    Secure deletion of a member with confirmation page prompt.
    """
    conn = database.get_db_connection()
    member = conn.execute("SELECT * FROM members WHERE id = ?;", (id,)).fetchone()

    if not member:
        conn.close()
        flash("Member record not found.", "danger")
        return redirect(url_for('members_list'))

    if request.method == 'POST':
        member_name = member['full_name']
        member_code = member['member_id']
        conn.execute("DELETE FROM members WHERE id = ?;", (id,))
        conn.commit()
        conn.close()

        flash(f"Member '{member_name}' ({member_code}) and all associated records permanently deleted.", "info")
        return redirect(url_for('members_list'))

    # GET request renders confirm_delete.html
    conn.close()
    return render_template(
        'confirm_delete.html',
        item_type="Member",
        item_title=f"{member['full_name']} ({member['member_id']})",
        item_details={
            "Member ID": member['member_id'],
            "Full Name": member['full_name'],
            "Email": member['email'],
            "Phone": member['phone'],
            "Expiry Date": member['expiry_date']
        },
        warning_message="Deleting this member will permanently remove their profile, attendance logs, and payment receipts from the database.",
        cancel_url=url_for('member_details', id=id),
        delete_url=url_for('delete_member', id=id)
    )


# -------------------------------------------------------------------------
# MEMBERSHIP PLANS MANAGEMENT
# -------------------------------------------------------------------------
@app.route('/plans', methods=['GET', 'POST'])
@login_required
def membership_plans():
    """
    Lists all configurable membership plans and allows adding new plans.
    """
    conn = database.get_db_connection()

    if request.method == 'POST':
        plan_name = request.form.get('plan_name', '').strip()
        duration_days = request.form.get('duration_days', '').strip()
        price = request.form.get('price', '').strip()
        description = request.form.get('description', '').strip()

        if not plan_name or not duration_days or not price:
            flash("Plan name, duration, and price are required.", "danger")
            conn.close()
            return redirect(url_for('membership_plans'))

        try:
            dur_int = int(duration_days)
            price_float = round(float(price), 2)
            if dur_int <= 0 or price_float < 0:
                raise ValueError()
        except ValueError:
            flash("Duration must be a positive integer and price must be a valid number.", "danger")
            conn.close()
            return redirect(url_for('membership_plans'))

        try:
            conn.execute("""
                INSERT INTO membership_plans (plan_name, duration_days, price, description)
                VALUES (?, ?, ?, ?);
            """, (plan_name, dur_int, price_float, description))
            conn.commit()
            flash(f"Membership plan '{plan_name}' created successfully!", "success")
        except sqlite3.IntegrityError:
            flash(f"A plan named '{plan_name}' already exists. Please choose a unique name.", "danger")

        conn.close()
        return redirect(url_for('membership_plans'))

    # GET: fetch plans with active member count
    plans_rows = conn.execute("""
        SELECT p.*, COUNT(m.id) as enrolled_count
        FROM membership_plans p
        LEFT JOIN members m ON p.id = m.plan_id
        GROUP BY p.id
        ORDER BY p.duration_days ASC;
    """).fetchall()

    conn.close()
    return render_template('membership_plans.html', plans=plans_rows)


@app.route('/plans/<int:id>/edit', methods=['POST'])
@login_required
def edit_plan(id):
    """
    Updates an existing membership plan.
    """
    plan_name = request.form.get('plan_name', '').strip()
    duration_days = request.form.get('duration_days', '').strip()
    price = request.form.get('price', '').strip()
    description = request.form.get('description', '').strip()

    if not plan_name or not duration_days or not price:
        flash("All fields are required to update plan.", "danger")
        return redirect(url_for('membership_plans'))

    try:
        dur_int = int(duration_days)
        price_float = round(float(price), 2)
        if dur_int <= 0 or price_float < 0:
            raise ValueError()
    except ValueError:
        flash("Invalid duration or price format.", "danger")
        return redirect(url_for('membership_plans'))

    conn = database.get_db_connection()
    try:
        conn.execute("""
            UPDATE membership_plans
            SET plan_name = ?, duration_days = ?, price = ?, description = ?
            WHERE id = ?;
        """, (plan_name, dur_int, price_float, description, id))
        conn.commit()
        flash(f"Plan '{plan_name}' updated successfully.", "success")
    except sqlite3.IntegrityError:
        flash(f"Another plan with the name '{plan_name}' already exists.", "danger")

    conn.close()
    return redirect(url_for('membership_plans'))


@app.route('/plans/<int:id>/delete', methods=['POST'])
@login_required
def delete_plan(id):
    """
    Deletes a plan if no members are currently enrolled under it.
    """
    conn = database.get_db_connection()
    members_count = conn.execute(
        "SELECT COUNT(*) FROM members WHERE plan_id = ?;",
        (id,)
    ).fetchone()[0]

    if members_count > 0:
        conn.close()
        flash(f"Cannot delete plan: {members_count} member(s) are currently assigned to it.", "danger")
        return redirect(url_for('membership_plans'))

    conn.execute("DELETE FROM membership_plans WHERE id = ?;", (id,))
    conn.commit()
    conn.close()
    flash("Membership plan deleted successfully.", "info")
    return redirect(url_for('membership_plans'))


# -------------------------------------------------------------------------
# TRAINER MANAGEMENT (CRUD)
# -------------------------------------------------------------------------
@app.route('/trainers', methods=['GET', 'POST'])
@login_required
def trainers():
    """
    Trainer management view: lists trainers with search and filter,
    and processes trainer addition.
    """
    conn = database.get_db_connection()

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        specialization = request.form.get('specialization', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        experience = request.form.get('experience', '').strip()
        salary = request.form.get('salary', '').strip()
        availability = request.form.get('availability', 'Full-time').strip()

        if not full_name or not specialization or not phone or not email or not experience or not salary:
            flash("All trainer details are required.", "danger")
            conn.close()
            return redirect(url_for('trainers'))

        try:
            exp_int = int(experience)
            sal_float = round(float(salary), 2)
            if exp_int < 0 or sal_float < 0:
                raise ValueError()
        except ValueError:
            flash("Experience and salary must be non-negative numbers.", "danger")
            conn.close()
            return redirect(url_for('trainers'))

        trainer_id = database.generate_next_trainer_id()
        conn.execute("""
            INSERT INTO trainers (
                trainer_id, full_name, specialization, phone, email, experience, salary, availability
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (trainer_id, full_name, specialization, phone, email, exp_int, sal_float, availability))
        conn.commit()
        conn.close()

        flash(f"Trainer '{full_name}' ({trainer_id}) added successfully!", "success")
        return redirect(url_for('trainers'))

    # GET filter & search
    search_query = request.args.get('q', '').strip()
    availability_filter = request.args.get('availability', '').strip()

    query = "SELECT * FROM trainers WHERE 1=1"
    params = []

    if search_query:
        query += " AND (trainer_id LIKE ? OR full_name LIKE ? OR specialization LIKE ?)"
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term, like_term])

    if availability_filter in ['Full-time', 'Part-time']:
        query += " AND availability = ?"
        params.append(availability_filter)

    query += " ORDER BY id DESC;"
    trainers_list = conn.execute(query, params).fetchall()
    next_trainer_id = database.generate_next_trainer_id()
    conn.close()

    return render_template(
        'trainers.html',
        trainers=trainers_list,
        next_trainer_id=next_trainer_id,
        search_query=search_query,
        availability_filter=availability_filter
    )


@app.route('/trainers/<int:id>/edit', methods=['POST'])
@login_required
def edit_trainer(id):
    """
    Updates an existing trainer profile.
    """
    full_name = request.form.get('full_name', '').strip()
    specialization = request.form.get('specialization', '').strip()
    phone = request.form.get('phone', '').strip()
    email = request.form.get('email', '').strip()
    experience = request.form.get('experience', '').strip()
    salary = request.form.get('salary', '').strip()
    availability = request.form.get('availability', 'Full-time').strip()

    if not full_name or not specialization or not phone or not email or not experience or not salary:
        flash("All trainer fields must be completed.", "danger")
        return redirect(url_for('trainers'))

    try:
        exp_int = int(experience)
        sal_float = round(float(salary), 2)
    except ValueError:
        flash("Invalid numeric value for experience or salary.", "danger")
        return redirect(url_for('trainers'))

    conn = database.get_db_connection()
    conn.execute("""
        UPDATE trainers
        SET full_name = ?, specialization = ?, phone = ?, email = ?,
            experience = ?, salary = ?, availability = ?
        WHERE id = ?;
    """, (full_name, specialization, phone, email, exp_int, sal_float, availability, id))
    conn.commit()
    conn.close()

    flash(f"Trainer '{full_name}' updated successfully.", "success")
    return redirect(url_for('trainers'))


@app.route('/trainers/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete_trainer(id):
    """
    Deletes a trainer with a confirmation screen.
    """
    conn = database.get_db_connection()
    trainer = conn.execute("SELECT * FROM trainers WHERE id = ?;", (id,)).fetchone()

    if not trainer:
        conn.close()
        flash("Trainer record not found.", "danger")
        return redirect(url_for('trainers'))

    if request.method == 'POST':
        name = trainer['full_name']
        t_id = trainer['trainer_id']
        conn.execute("DELETE FROM trainers WHERE id = ?;", (id,))
        conn.commit()
        conn.close()
        flash(f"Trainer '{name}' ({t_id}) removed from system.", "info")
        return redirect(url_for('trainers'))

    conn.close()
    return render_template(
        'confirm_delete.html',
        item_type="Trainer",
        item_title=f"{trainer['full_name']} ({trainer['trainer_id']})",
        item_details={
            "Trainer ID": trainer['trainer_id'],
            "Full Name": trainer['full_name'],
            "Specialization": trainer['specialization'],
            "Availability": trainer['availability'],
            "Salary": f"₹{trainer['salary']:,.2f}"
        },
        warning_message="Are you sure you want to remove this trainer from the system?",
        cancel_url=url_for('trainers'),
        delete_url=url_for('delete_trainer', id=id)
    )


# -------------------------------------------------------------------------
# PAYMENT MANAGEMENT & RECEIPT GENERATOR
# -------------------------------------------------------------------------
@app.route('/payments', methods=['GET', 'POST'])
@login_required
def payments():
    """
    Payment management: records new payments, filters payment records,
    and displays financial summary metrics.
    """
    conn = database.get_db_connection()

    if request.method == 'POST':
        member_id = request.form.get('member_id', '').strip()
        amount = request.form.get('amount', '').strip()
        payment_method = request.form.get('payment_method', 'Cash').strip()
        payment_date = request.form.get('payment_date', '').strip() or date.today().isoformat()
        status = request.form.get('status', 'Completed').strip()

        if not member_id or not amount:
            flash("Member selection and payment amount are required.", "danger")
            conn.close()
            return redirect(url_for('payments'))

        try:
            amt_float = round(float(amount), 2)
            if amt_float <= 0:
                raise ValueError()
        except ValueError:
            flash("Payment amount must be a positive number.", "danger")
            conn.close()
            return redirect(url_for('payments'))

        payment_id = database.generate_next_payment_id()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO payments (
                payment_id, member_id, amount, payment_method, payment_date, status
            ) VALUES (?, ?, ?, ?, ?, ?);
        """, (payment_id, int(member_id), amt_float, payment_method, payment_date, status))
        new_pay_id = cursor.lastrowid
        conn.commit()
        conn.close()

        flash(f"Payment {payment_id} of ₹{amt_float:.2f} recorded successfully!", "success")
        return redirect(url_for('receipt', id=new_pay_id))

    # GET: search & filter payments
    search_query = request.args.get('q', '').strip()
    method_filter = request.args.get('method', '').strip()
    status_filter = request.args.get('status', '').strip()
    date_from = request.args.get('from', '').strip()
    date_to = request.args.get('to', '').strip()

    query = """
        SELECT p.*, m.member_id as member_code, m.full_name as member_name, m.phone as member_phone
        FROM payments p
        JOIN members m ON p.member_id = m.id
        WHERE 1=1
    """
    params = []

    if search_query:
        query += " AND (p.payment_id LIKE ? OR m.member_id LIKE ? OR m.full_name LIKE ?)"
        term = f"%{search_query}%"
        params.extend([term, term, term])

    if method_filter:
        query += " AND p.payment_method = ?"
        params.append(method_filter)

    if status_filter:
        query += " AND p.status = ?"
        params.append(status_filter)

    if date_from:
        query += " AND p.payment_date >= ?"
        params.append(date_from)

    if date_to:
        query += " AND p.payment_date <= ?"
        params.append(date_to)

    query += " ORDER BY p.id DESC;"

    payments_list = conn.execute(query, params).fetchall()

    # Financial Summary Metrics
    total_rev = conn.execute("SELECT COALESCE(SUM(amount), 0.0) FROM payments WHERE status = 'Completed';").fetchone()[0]
    upi_total = conn.execute("SELECT COALESCE(SUM(amount), 0.0) FROM payments WHERE status = 'Completed' AND payment_method = 'UPI';").fetchone()[0]
    cash_total = conn.execute("SELECT COALESCE(SUM(amount), 0.0) FROM payments WHERE status = 'Completed' AND payment_method = 'Cash';").fetchone()[0]
    card_total = conn.execute("SELECT COALESCE(SUM(amount), 0.0) FROM payments WHERE status = 'Completed' AND payment_method = 'Card';").fetchone()[0]

    # Active members dropdown list for recording new payment
    members_dropdown = conn.execute("""
        SELECT m.id, m.member_id, m.full_name, p.plan_name, p.price
        FROM members m
        JOIN membership_plans p ON m.plan_id = p.id
        ORDER BY m.full_name ASC;
    """).fetchall()

    next_payment_id = database.generate_next_payment_id()
    conn.close()

    return render_template(
        'payments.html',
        payments=payments_list,
        members=members_dropdown,
        next_payment_id=next_payment_id,
        total_rev=round(total_rev, 2),
        upi_total=round(upi_total, 2),
        cash_total=round(cash_total, 2),
        card_total=round(card_total, 2),
        search_query=search_query,
        method_filter=method_filter,
        status_filter=status_filter,
        date_from=date_from,
        date_to=date_to
    )


@app.route('/payments/<int:id>/receipt')
@login_required
def receipt(id):
    """
    Generates a clean, professional HTML/CSS payment receipt.
    Cleanly printable with @media print.
    """
    conn = database.get_db_connection()
    receipt_data = conn.execute("""
        SELECT p.*, m.member_id as member_code, m.full_name as member_name,
               m.phone as member_phone, m.email as member_email, m.address as member_address,
               pl.plan_name, pl.duration_days
        FROM payments p
        JOIN members m ON p.member_id = m.id
        JOIN membership_plans pl ON m.plan_id = pl.id
        WHERE p.id = ?;
    """, (id,)).fetchone()

    conn.close()

    if not receipt_data:
        flash("Payment receipt not found.", "danger")
        return redirect(url_for('payments'))

    return render_template('receipt.html', receipt=receipt_data)


# -------------------------------------------------------------------------
# ATTENDANCE MANAGEMENT
# -------------------------------------------------------------------------
@app.route('/attendance', methods=['GET', 'POST'])
@login_required
def attendance():
    """
    Manages daily attendance check-ins with SQLite UNIQUE constraint,
    prevents duplicate entries, and displays check-in history.
    """
    conn = database.get_db_connection()
    today_str = date.today().isoformat()
    selected_date = request.args.get('date', today_str).strip()

    if request.method == 'POST':
        member_id = request.form.get('member_id', '').strip()
        custom_time = request.form.get('check_in_time', '').strip() or datetime.now().strftime("%H:%M:%S")

        if not member_id:
            flash("Please select a member to mark attendance.", "danger")
            conn.close()
            return redirect(url_for('attendance', date=selected_date))

        # Check if member exists
        member = conn.execute("SELECT * FROM members WHERE id = ?;", (int(member_id),)).fetchone()
        if not member:
            flash("Selected member was not found in the database.", "danger")
            conn.close()
            return redirect(url_for('attendance', date=selected_date))

        # Check membership status for informative warning
        status, _ = database.get_member_status(member['expiry_date'])
        status_warning = ""
        if status == "Expired":
            status_warning = " (Note: Membership has expired!)"

        # Attempt insertion with SQLite UNIQUE constraint check
        try:
            conn.execute("""
                INSERT INTO attendance (member_id, attendance_date, check_in_time)
                VALUES (?, ?, ?);
            """, (int(member_id), today_str, custom_time))
            conn.commit()
            flash(f"Check-in recorded for {member['full_name']} ({member['member_id']}) at {custom_time}!{status_warning}", "success")
        except sqlite3.IntegrityError:
            flash(f"Duplicate entry: {member['full_name']} ({member['member_id']}) has ALREADY checked in for today ({today_str})!", "warning")

        conn.close()
        return redirect(url_for('attendance', date=today_str))

    # GET: fetch attendance for the selected date
    attendance_records = conn.execute("""
        SELECT a.id, a.attendance_date, a.check_in_time, a.check_out_time,
               m.id as member_row_id, m.member_id as member_code, m.full_name as member_name,
               m.phone as member_phone, m.expiry_date, p.plan_name
        FROM attendance a
        JOIN members m ON a.member_id = m.id
        JOIN membership_plans p ON m.plan_id = p.id
        WHERE a.attendance_date = ?
        ORDER BY (a.check_out_time IS NOT NULL), a.check_in_time DESC;
    """, (selected_date,)).fetchall()

    # Enhance rows with membership status and checkout/duration info
    formatted_records = []
    currently_in_gym_count = 0
    for r in attendance_records:
        m_status, _ = database.get_member_status(r['expiry_date'])
        is_in_gym = not r['check_out_time']
        if is_in_gym:
            currently_in_gym_count += 1
        dur = calculate_duration(r['check_in_time'], r['check_out_time'])
        formatted_records.append({
            'id': r['id'],
            'member_row_id': r['member_row_id'],
            'member_code': r['member_code'],
            'member_name': r['member_name'],
            'member_phone': r['member_phone'],
            'check_in_time': r['check_in_time'],
            'check_out_time': r['check_out_time'],
            'is_in_gym': is_in_gym,
            'duration': dur,
            'plan_name': r['plan_name'],
            'membership_status': m_status
        })

    # Available members list for quick check-in dropdown
    all_members = conn.execute("""
        SELECT m.id, m.member_id, m.full_name, m.expiry_date, p.plan_name
        FROM members m
        JOIN membership_plans p ON m.plan_id = p.id
        ORDER BY m.full_name ASC;
    """).fetchall()

    members_for_checkin = []
    for m in all_members:
        m_stat, _ = database.get_member_status(m['expiry_date'])
        members_for_checkin.append({
            'id': m['id'],
            'member_id': m['member_id'],
            'full_name': m['full_name'],
            'plan_name': m['plan_name'],
            'status': m_stat
        })

    # Daily count statistics
    today_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE attendance_date = ?;", (today_str,)).fetchone()[0]
    selected_date_count = len(formatted_records)
    total_active_members = conn.execute("SELECT COUNT(*) FROM members WHERE expiry_date >= ?;", (today_str,)).fetchone()[0]

    conn.close()

    return render_template(
        'attendance.html',
        attendance_records=formatted_records,
        members=members_for_checkin,
        selected_date=selected_date,
        today_date=today_str,
        today_count=today_count,
        currently_in_gym_count=currently_in_gym_count,
        selected_date_count=selected_date_count,
        total_active_members=total_active_members
    )


@app.route('/attendance/<int:id>/delete', methods=['POST'])
@login_required
def delete_attendance(id):
    """
    Deletes an erroneous attendance check-in entry.
    """
    selected_date = request.form.get('selected_date', date.today().isoformat())
    conn = database.get_db_connection()
    conn.execute("DELETE FROM attendance WHERE id = ?;", (id,))
    conn.commit()
    conn.close()
    flash("Attendance record removed.", "info")
    return redirect(url_for('attendance', date=selected_date))


# -------------------------------------------------------------------------
# REPORTS & CSV EXPORTS
# -------------------------------------------------------------------------
@app.route('/reports')
@login_required
def reports():
    """
    Comprehensive reporting interface supporting Member, Financial,
    Attendance, and Expiration reports with live server-side filtering.
    """
    report_type = request.args.get('type', 'members').strip()
    status_filter = request.args.get('status', 'all').strip()
    plan_filter = request.args.get('plan_id', '').strip()
    date_from = request.args.get('from', '').strip()
    date_to = request.args.get('to', '').strip()

    conn = database.get_db_connection()
    today_str = date.today().isoformat()

    report_data = []
    summary = {}

    if report_type == 'members':
        query = """
            SELECT m.*, p.plan_name, p.price
            FROM members m
            JOIN membership_plans p ON m.plan_id = p.id
            WHERE 1=1
        """
        params = []
        if status_filter == 'active':
            query += " AND m.expiry_date >= ?"
            params.append(today_str)
        elif status_filter == 'expired':
            query += " AND m.expiry_date < ?"
            params.append(today_str)

        if plan_filter and plan_filter.isdigit():
            query += " AND m.plan_id = ?"
            params.append(int(plan_filter))

        if date_from:
            query += " AND m.registration_date >= ?"
            params.append(date_from)
        if date_to:
            query += " AND m.registration_date <= ?"
            params.append(date_to)

        query += " ORDER BY m.registration_date DESC;"
        rows = conn.execute(query, params).fetchall()

        for r in rows:
            st, d_left = database.get_member_status(r['expiry_date'])
            report_data.append({
                'id': r['member_id'],
                'name': r['full_name'],
                'age_gender': f"{r['age']} / {r['gender']}",
                'contact': f"{r['phone']} | {r['email']}",
                'plan': r['plan_name'],
                'start_date': r['start_date'],
                'expiry_date': r['expiry_date'],
                'status': st,
                'days_left': d_left
            })
        summary = {
            'total_count': len(report_data),
            'active_count': sum(1 for m in report_data if m['status'] == 'Active'),
            'expired_count': sum(1 for m in report_data if m['status'] == 'Expired')
        }

    elif report_type == 'revenue':
        query = """
            SELECT p.*, m.member_id as member_code, m.full_name as member_name
            FROM payments p
            JOIN members m ON p.member_id = m.id
            WHERE 1=1
        """
        params = []
        if status_filter in ['Completed', 'Pending', 'Failed']:
            query += " AND p.status = ?"
            params.append(status_filter)

        if date_from:
            query += " AND p.payment_date >= ?"
            params.append(date_from)
        if date_to:
            query += " AND p.payment_date <= ?"
            params.append(date_to)

        query += " ORDER BY p.payment_date DESC;"
        rows = conn.execute(query, params).fetchall()

        total_sum = 0.0
        for r in rows:
            if r['status'] == 'Completed':
                total_sum += r['amount']
            report_data.append({
                'id': r['payment_id'],
                'member': f"{r['member_name']} ({r['member_code']})",
                'amount': f"₹{r['amount']:.2f}",
                'method': r['payment_method'],
                'date': r['payment_date'],
                'status': r['status']
            })
        summary = {
            'total_transactions': len(report_data),
            'total_amount': f"₹{total_sum:,.2f}"
        }

    elif report_type == 'attendance':
        query = """
            SELECT a.*, m.member_id as member_code, m.full_name as member_name, p.plan_name
            FROM attendance a
            JOIN members m ON a.member_id = m.id
            JOIN membership_plans p ON m.plan_id = p.id
            WHERE 1=1
        """
        params = []
        if date_from:
            query += " AND a.attendance_date >= ?"
            params.append(date_from)
        if date_to:
            query += " AND a.attendance_date <= ?"
            params.append(date_to)

        query += " ORDER BY a.attendance_date DESC, a.check_in_time DESC;"
        rows = conn.execute(query, params).fetchall()

        for r in rows:
            report_data.append({
                'date': r['attendance_date'],
                'time': r['check_in_time'],
                'member': f"{r['member_name']} ({r['member_code']})",
                'plan': r['plan_name']
            })
        summary = {
            'total_checkins': len(report_data)
        }

    elif report_type == 'expiring':
        days_ahead = 7
        try:
            days_ahead = int(request.args.get('days', 7))
        except ValueError:
            days_ahead = 7

        limit_date_str = (date.today() + timedelta(days=days_ahead)).isoformat()
        rows = conn.execute("""
            SELECT m.*, p.plan_name
            FROM members m
            JOIN membership_plans p ON m.plan_id = p.id
            WHERE m.expiry_date >= ? AND m.expiry_date <= ?
            ORDER BY m.expiry_date ASC;
        """, (today_str, limit_date_str)).fetchall()

        for r in rows:
            _, d_left = database.get_member_status(r['expiry_date'])
            report_data.append({
                'id': r['member_id'],
                'name': r['full_name'],
                'phone': r['phone'],
                'email': r['email'],
                'plan': r['plan_name'],
                'expiry_date': r['expiry_date'],
                'days_left': d_left
            })
        summary = {
            'expiring_count': len(report_data),
            'window_days': days_ahead
        }

    plans = conn.execute("SELECT id, plan_name FROM membership_plans ORDER BY id ASC;").fetchall()
    conn.close()

    return render_template(
        'reports.html',
        report_type=report_type,
        report_data=report_data,
        summary=summary,
        plans=plans,
        status_filter=status_filter,
        plan_filter=plan_filter,
        date_from=date_from,
        date_to=date_to
    )


@app.route('/reports/export-csv')
@login_required
def export_csv():
    """
    Streams dynamic CSV file generated directly using Python's standard csv.writer.
    """
    report_type = request.args.get('type', 'members').strip()
    conn = database.get_db_connection()
    today_str = date.today().isoformat()

    si = io.StringIO()
    writer = csv.writer(si)

    filename = f"gym_{report_type}_report_{today_str}.csv"

    if report_type == 'members':
        writer.writerow([
            'Member ID', 'Full Name', 'Age', 'Gender', 'Phone', 'Email',
            'Address', 'Registration Date', 'Plan Name', 'Price', 'Start Date',
            'Expiry Date', 'Status', 'Days Remaining'
        ])
        rows = conn.execute("""
            SELECT m.*, p.plan_name, p.price
            FROM members m
            JOIN membership_plans p ON m.plan_id = p.id
            ORDER BY m.id ASC;
        """).fetchall()

        for r in rows:
            status, days_left = database.get_member_status(r['expiry_date'])
            writer.writerow([
                r['member_id'], r['full_name'], r['age'], r['gender'], r['phone'],
                r['email'], r['address'] or '', r['registration_date'], r['plan_name'],
                r['price'], r['start_date'], r['expiry_date'], status, days_left
            ])

    elif report_type == 'revenue' or report_type == 'payments':
        writer.writerow([
            'Payment ID', 'Member ID', 'Member Name', 'Amount',
            'Payment Method', 'Payment Date', 'Status'
        ])
        rows = conn.execute("""
            SELECT p.*, m.member_id as member_code, m.full_name as member_name
            FROM payments p
            JOIN members m ON p.member_id = m.id
            ORDER BY p.id ASC;
        """).fetchall()

        for r in rows:
            writer.writerow([
                r['payment_id'], r['member_code'], r['member_name'],
                r['amount'], r['payment_method'], r['payment_date'], r['status']
            ])

    elif report_type == 'attendance':
        writer.writerow([
            'Attendance Date', 'Check-In Time', 'Member ID', 'Member Name', 'Membership Plan'
        ])
        rows = conn.execute("""
            SELECT a.attendance_date, a.check_in_time, m.member_id, m.full_name, p.plan_name
            FROM attendance a
            JOIN members m ON a.member_id = m.id
            JOIN membership_plans p ON m.plan_id = p.id
            ORDER BY a.attendance_date DESC, a.check_in_time DESC;
        """).fetchall()

        for r in rows:
            writer.writerow([
                r['attendance_date'], r['check_in_time'], r['member_id'],
                r['full_name'], r['plan_name']
            ])

    elif report_type == 'expiring':
        writer.writerow([
            'Member ID', 'Full Name', 'Phone', 'Email', 'Plan Name',
            'Start Date', 'Expiry Date', 'Days Remaining'
        ])
        limit_date_str = (date.today() + timedelta(days=14)).isoformat()
        rows = conn.execute("""
            SELECT m.*, p.plan_name
            FROM members m
            JOIN membership_plans p ON m.plan_id = p.id
            WHERE m.expiry_date >= ? AND m.expiry_date <= ?
            ORDER BY m.expiry_date ASC;
        """, (today_str, limit_date_str)).fetchall()

        for r in rows:
            _, days_left = database.get_member_status(r['expiry_date'])
            writer.writerow([
                r['member_id'], r['full_name'], r['phone'], r['email'],
                r['plan_name'], r['start_date'], r['expiry_date'], days_left
            ])

    conn.close()

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    output.headers["Content-type"] = "text/csv; charset=utf-8"
    return output


# -------------------------------------------------------------------------
# SETTINGS & ADMIN ACCOUNT MANAGEMENT
# -------------------------------------------------------------------------
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """
    Administrative Settings:
    1. Allows password modification for the logged-in admin.
    2. Displays SQLite system metrics, table counts, and database file metadata.
    """
    conn = database.get_db_connection()

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not current_password or not new_password or not confirm_password:
            flash("All password fields are required.", "danger")
            conn.close()
            return redirect(url_for('settings'))

        if new_password != confirm_password:
            flash("New password and confirmation password do not match.", "danger")
            conn.close()
            return redirect(url_for('settings'))

        if len(new_password) < 6:
            flash("New password must be at least 6 characters long.", "danger")
            conn.close()
            return redirect(url_for('settings'))

        user = conn.execute("SELECT * FROM users WHERE id = ?;", (session['user_id'],)).fetchone()
        if not user or not check_password_hash(user['password_hash'], current_password):
            flash("Incorrect current password.", "danger")
            conn.close()
            return redirect(url_for('settings'))

        new_hash = generate_password_hash(new_password)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?;", (new_hash, session['user_id']))
        conn.commit()
        conn.close()

        flash("Admin password updated successfully! Please keep your new credentials safe.", "success")
        return redirect(url_for('settings'))

    # System & Database Overview
    db_size_bytes = os.path.getsize(database.DB_PATH) if os.path.exists(database.DB_PATH) else 0
    db_size_kb = round(db_size_bytes / 1024, 2)

    sqlite_ver = conn.execute("SELECT sqlite_version();").fetchone()[0]
    total_users = conn.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
    total_members = conn.execute("SELECT COUNT(*) FROM members;").fetchone()[0]
    total_plans = conn.execute("SELECT COUNT(*) FROM membership_plans;").fetchone()[0]
    total_trainers = conn.execute("SELECT COUNT(*) FROM trainers;").fetchone()[0]
    total_payments = conn.execute("SELECT COUNT(*) FROM payments;").fetchone()[0]
    total_attendance = conn.execute("SELECT COUNT(*) FROM attendance;").fetchone()[0]

    conn.close()

    db_stats = {
        'path': database.DB_PATH,
        'size_kb': db_size_kb,
        'sqlite_version': sqlite_ver,
        'users_count': total_users,
        'members_count': total_members,
        'plans_count': total_plans,
        'trainers_count': total_trainers,
        'payments_count': total_payments,
        'attendance_count': total_attendance
    }

    return render_template('settings.html', db_stats=db_stats)


@app.route('/settings/clear-data', methods=['POST'])
@login_required
def clear_system_data():
    """
    Clears all operational member records, attendance logs, payment receipts,
    and trainer profiles so the user can start completely fresh with their own data.
    Keeps the admin user and configured membership plans intact.
    """
    database.clear_all_operational_data()
    flash("System data successfully cleared! All members, trainers, attendance logs, and payments have been wiped. You now have a clean slate to create your own custom data.", "success")
    return redirect(url_for('settings'))


# -------------------------------------------------------------------------
# ERROR HANDLING
# -------------------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    """
    Custom 404 Error handler matching the Dark Fitness theme.
    """
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """
    Custom 500 Error handler.
    """
    return render_template('404.html', error_code=500, error_message="Internal Server Error occurred."), 500


# -------------------------------------------------------------------------
# MAIN EXECUTION ENTRYPOINT
# -------------------------------------------------------------------------
if __name__ == '__main__':
    # Respect Render/cloud PORT environment variable, fallback to 5000 for local dev
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
