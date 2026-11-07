import os
import re
from datetime import datetime

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, g, abort)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import DictCursor

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")

# Database configuration: Kukuha sa Render Environment Variable (Supabase), o gagamit ng local SQLite
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

NETWORKS = ["Globe", "Smart", "Sun", "TNT", "TM", "DITO", "GOMO"]

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123456")

PHONE_RE = re.compile(r"^\d{11}$")

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "warning"


# ---------------------------------------------------------------------------
# Database helpers (Compatible with both PostgreSQL and SQLite)
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        if DATABASE_URL:
            g.db = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
        else:
            import sqlite3
            BASE_DIR = os.path.abspath(os.path.dirname(__file__))
            DATABASE = os.path.join(BASE_DIR, "phonebook.db")
            g.db = sqlite3.connect(DATABASE)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if DATABASE_URL:
        db = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                phone TEXT UNIQUE,
                network TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                created_at TEXT NOT NULL
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id SERIAL PRIMARY KEY,
                integer_user_id INTEGER,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                network TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        cursor.execute("SELECT 1 FROM users WHERE role = 'admin'")
        exists = cursor.fetchone()
        if not exists:
            cursor.execute(
                "INSERT INTO users (username, phone, network, password_hash, role, created_at) "
                "VALUES (%s, NULL, NULL, %s, 'admin', %s)",
                (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), now_str()),
            )
        db.commit()
        cursor.close()
        db.close()
    else:
        import sqlite3
        BASE_DIR = os.path.abspath(os.path.dirname(__file__))
        DATABASE = os.path.join(BASE_DIR, "phonebook.db")
        db = sqlite3.connect(DATABASE)
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                phone TEXT UNIQUE,
                network TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                network TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        exists = db.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone()
        if not exists:
            db.execute(
                "INSERT INTO users (username, phone, network, password_hash, role, created_at) "
                "VALUES (?, NULL, NULL, ?, 'admin', ?)",
                (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), now_str()),
            )
        db.commit()
        db.close()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %I:%M %p")


with app.app_context():
    init_db()


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------
class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.phone = row["phone"]
        self.network = row["network"]
        self.role = row["role"]


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor() if DATABASE_URL else db
    cursor.execute("SELECT * FROM users WHERE id = %s" if DATABASE_URL else "SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    return User(row) if row else None


def member_required(view):
    from functools import wraps

    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "member":
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    from functools import wraps

    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------
@app.route("/")
def frontpage():
    return render_template("frontpage.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        phone = request.form.get("phone", "").strip()
        network = request.form.get("network", "")
        password = request.form.get("password", "")

        if not username or not phone or not password:
            flash("All fields are required.", "danger")
        elif username.lower() == ADMIN_USERNAME.lower():
            flash("That account name is reserved.", "danger")
        elif not PHONE_RE.match(phone):
            flash("Mobile number must be exactly 11 digits.", "danger")
        elif network not in NETWORKS:
            flash("Please choose a valid network.", "danger")
        else:
            db = get_db()
            cursor = db.cursor() if DATABASE_URL else db
            
            check_sql = "SELECT 1 FROM users WHERE phone = %s OR LOWER(username) = LOWER(%s)" if DATABASE_URL else "SELECT 1 FROM users WHERE phone = ? OR LOWER(username) = LOWER(?)"
            cursor.execute(check_sql, (phone, username))
            taken = cursor.fetchone()
            
            if taken:
                flash("That name or mobile number is already registered.", "danger")
            else:
                insert_sql = "INSERT INTO users (username, phone, network, password_hash, role, created_at) VALUES (%s, %s, %s, %s, 'member', %s)" if DATABASE_URL else "INSERT INTO users (username, phone, network, password_hash, role, created_at) VALUES (?, ?, ?, ?, 'member', ?)"
                cursor.execute(insert_sql, (username, phone, network, generate_password_hash(password), now_str()))
                db.commit()
                flash("Account created! You can now log in.", "success")
                return redirect(url_for("login"))

    return render_template("register.html", networks=NETWORKS)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        login_input = request.form.get("login_input", "").strip()
        network = request.form.get("network", "")
        password = request.form.get("password", "")
        db = get_db()
        cursor = db.cursor() if DATABASE_URL else db

        admin_sql = "SELECT * FROM users WHERE role = 'admin' AND LOWER(username) = LOWER(%s)" if DATABASE_URL else "SELECT * FROM users WHERE role = 'admin' AND LOWER(username) = LOWER(?)"
        cursor.execute(admin_sql, (login_input,))
        row = cursor.fetchone()

        if row is None:
            member_sql = "SELECT * FROM users WHERE role = 'member' AND phone = %s" if DATABASE_URL else "SELECT * FROM users WHERE role = 'member' AND phone = ?"
            cursor.execute(member_sql, (login_input,))
            row = cursor.fetchone()
            if row is not None and row["network"] != network:
                row = None

        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row))
            flash(f"Welcome back, {row['username']}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid login details. Check your number, network and password.", "danger")

    return render_template("login.html", networks=NETWORKS)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("frontpage"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor() if DATABASE_URL else db

    if request.method == "POST":
        if current_user.role != "member":
            abort(403)
        action = request.form.get("action")

        if action == "add_contact":
            name = request.form.get("name", "").strip()
            phone = request.form.get("phone", "").strip()
            network = request.form.get("network", "")
            if not name:
                flash("Contact name is required.", "danger")
            elif not PHONE_RE.match(phone):
                flash("Phone number must be exactly 11 digits.", "danger")
            elif network not in NETWORKS:
                flash("Please choose a valid network.", "danger")
            else:
                chk_sql = "SELECT 1 FROM contacts WHERE user_id = %s AND phone = %s" if DATABASE_URL else "SELECT 1 FROM contacts WHERE user_id = ? AND phone = ?"
                cursor.execute(chk_sql, (current_user.id, phone))
                if cursor.fetchone():
                    flash("You already saved a contact with that number.", "warning")
                else:
                    ins_sql = "INSERT INTO contacts (user_id, name, phone, network) VALUES (%s, %s, %s, %s)" if DATABASE_URL else "INSERT INTO contacts (user_id, name, phone, network) VALUES (?, ?, ?, ?)"
                    cursor.execute(ins_sql, (current_user.id, name, phone, network))
                    db.commit()
                    flash("Contact saved.", "success")

        elif action == "edit_profile":
            username = request.form.get("username", "").strip()
            phone = request.form.get("phone", "").strip()
            network = request.form.get("network", "")
            if not username:
                flash("Username is required.", "danger")
            elif username.lower() == ADMIN_USERNAME.lower():
                flash("That account name is reserved.", "danger")
            elif not PHONE_RE.match(phone):
                flash("Mobile number must be exactly 11 digits.", "danger")
            elif network not in NETWORKS:
                flash("Please choose a valid network.", "danger")
            else:
                dup_sql = "SELECT 1 FROM users WHERE id != %s AND (phone = %s OR LOWER(username) = LOWER(%s))" if DATABASE_URL else "SELECT 1 FROM users WHERE id != ? AND (phone = ? OR LOWER(username) = LOWER(?))"
                cursor.execute(dup_sql, (current_user.id, phone, username))
                if cursor.fetchone():
                    flash("That name or mobile number is already used by another account.", "danger")
                else:
                    up_sql = "UPDATE users SET username = %s, phone = %s, network = %s WHERE id = %s" if DATABASE_URL else "UPDATE users SET username = ?, phone = ?, network = ? WHERE id = ?"
                    cursor.execute(up_sql, (username, phone, network, current_user.id))
                    db.commit()
                    flash("Profile updated.", "success")

        elif action == "change_password":
            old_pw = request.form.get("old_password", "")
            new_pw = request.form.get("new_password", "")
            pw_sql = "SELECT password_hash FROM users WHERE id = %s" if DATABASE_URL else "SELECT password_hash FROM users WHERE id = ?"
            cursor.execute(pw_sql, (current_user.id,))
            row = cursor.fetchone()
            if not check_password_hash(row["password_hash"], old_pw):
                flash("Current password is incorrect.", "danger")
            elif len(new_pw) < 6:
                flash("New password must be at least 6 characters.", "danger")
            else:
                up_pw_sql = "UPDATE users SET password_hash = %s WHERE id = %s" if DATABASE_URL else "UPDATE users SET password_hash = ? WHERE id = ?"
                cursor.execute(up_pw_sql, (generate_password_hash(new_pw), current_user.id))
                db.commit()
                flash("Password updated.", "success")

        return redirect(url_for("dashboard"))

    search_query = request.args.get("search", "").strip()
    like = f"%{search_query}%"

    if current_user.role == "admin":
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'member'")
        total_members = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM contacts")
        total_contacts = cursor.fetchone()[0]
        
        stats = {
            "total_members": total_members,
            "total_contacts": total_contacts,
        }
        sql = (
            "SELECT u.id, u.username, u.phone, u.network, u.created_at, "
            "COUNT(c.id) AS contacts_count "
            "FROM users u LEFT JOIN contacts c ON c.user_id = u.id "
            "WHERE u.role = 'member' "
        )
        params = []
        if search_query:
            sql += "AND (u.username LIKE %s OR u.phone LIKE %s) " if DATABASE_URL else "AND (u.username LIKE ? OR u.phone LIKE ?) "
            params += [like, like]
        sql += "GROUP BY u.id, u.username, u.phone, u.network, u.created_at ORDER BY u.id DESC"
        cursor.execute(sql, params)
        all_members = cursor.fetchall()
        return render_template("dashboard.html", stats=stats, all_members=all_members,
                               search_query=search_query, networks=NETWORKS)

    if search_query:
        c_sql = "SELECT * FROM contacts WHERE user_id = %s AND (name LIKE %s OR phone LIKE %s) ORDER BY name" if DATABASE_URL else "SELECT * FROM contacts WHERE user_id = ? AND (name LIKE ? OR phone LIKE ?) ORDER BY name COLLATE NOCASE"
        cursor.execute(c_sql, (current_user.id, like, like))
    else:
        c_sql = "SELECT * FROM contacts WHERE user_id = %s ORDER BY name" if DATABASE_URL else "SELECT * FROM contacts WHERE user_id = ? ORDER BY name COLLATE NOCASE"
        cursor.execute(c_sql, (current_user.id,))
    contacts = cursor.fetchall()
    
    u_sql = "SELECT * FROM users WHERE id = %s" if DATABASE_URL else "SELECT * FROM users WHERE id = ?"
    cursor.execute(u_sql, (current_user.id,))
    db_user = cursor.fetchone()
    
    return render_template("dashboard.html", contacts=contacts, db_user=db_user,
                           search_query=search_query, networks=NETWORKS)


# ---------------------------------------------------------------------------
# Contact edit / delete (members)
# ---------------------------------------------------------------------------
@app.route("/contact/<int:id>/update", methods=["GET", "POST"])
@member_required
def update_contact(id):
    db = get_db()
    cursor = db.cursor() if DATABASE_URL else db
    
    sel_sql = "SELECT * FROM contacts WHERE id = %s AND user_id = %s" if DATABASE_URL else "SELECT * FROM contacts WHERE id = ? AND user_id = ?"
    cursor.execute(sel_sql, (id, current_user.id))
    contact = cursor.fetchone()
    if contact is None:
        abort(404)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        network = request.form.get("network", "")
        if not name:
            flash("Contact name is required.", "danger")
        elif not PHONE_RE.match(phone):
            flash("Phone number must be exactly 11 digits.", "danger")
        elif network not in NETWORKS:
            flash("Please choose a valid network.", "danger")
        else:
            dup_c_sql = "SELECT 1 FROM contacts WHERE user_id = %s AND phone = %s AND id != %s" if DATABASE_URL else "SELECT 1 FROM contacts WHERE user_id = ? AND phone = ? AND id != ?"
            cursor.execute(dup_c_sql, (current_user.id, phone, id))
            if cursor.fetchone():
                flash("You already saved another contact with that number.", "warning")
            else:
                up_c_sql = "UPDATE contacts SET name = %s, phone = %s, network = %s WHERE id = %s" if DATABASE_URL else "UPDATE contacts SET name = ?, phone = ?, network = ? WHERE id = ?"
                cursor.execute(up_c_sql, (name, phone, network, id))
                db.commit()
                flash("Contact updated.", "success")
                return redirect(url_for("dashboard"))
        contact = {"id": id, "name": name, "phone": phone, "network": network}

    return render_template("update.html", contact=contact, networks=NETWORKS)


@app.route("/contact/<int:id>/delete")
@member_required
def delete_contact(id):
    db = get_db()
    cursor = db.cursor() if DATABASE_URL else db
    del_sql = "DELETE FROM contacts WHERE id = %s AND user_id = %s" if DATABASE_URL else "DELETE FROM contacts WHERE id = ? AND user_id = ?"
    cursor.execute(del_sql, (id, current_user.id))
    db.commit()
    flash("Contact deleted.", "info")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
@app.route("/admin/remove/<int:user_id>")
@admin_required
def admin_remove_user(user_id):
    db = get_db()
    cursor = db.cursor() if DATABASE_URL else db
    
    adm_sql = "SELECT * FROM users WHERE id = %s AND role = 'member'" if DATABASE_URL else "SELECT * FROM users WHERE id = ? AND role = 'member'"
    cursor.execute(adm_sql, (user_id,))
    user = cursor.fetchone()
    if user is None:
        flash("Member not found.", "danger")
    else:
        del_c_sql = "DELETE FROM contacts WHERE user_id = %s" if DATABASE_URL else "DELETE FROM contacts WHERE user_id = ?"
        del_u_sql = "DELETE FROM users WHERE id = %s" if DATABASE_URL else "DELETE FROM users WHERE id = ?"
        cursor.execute(del_c_sql, (user_id,))
        cursor.execute(del_u_sql, (user_id,))
        db.commit()
        flash(f"Member '{user['username']}' and all their contacts were removed.", "success")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
