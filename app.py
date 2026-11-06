import os
import re
import sqlite3
from datetime import datetime

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, g, abort)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "phonebook.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")

NETWORKS = ["Globe", "Smart", "Sun", "TNT", "TM", "DITO", "GOMO"]

# Default admin account (login with name "admin" – network is ignored for admin)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123456")

PHONE_RE = re.compile(r"^\d{11}$")

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "warning"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
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


# Awtomatikong i-initialize ang database kahit gumamit ng Gunicorn sa Render
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
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
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
            taken = db.execute(
                "SELECT 1 FROM users WHERE phone = ? OR LOWER(username) = LOWER(?)",
                (phone, username),
            ).fetchone()
            if taken:
                flash("That name or mobile number is already registered.", "danger")
            else:
                db.execute(
                    "INSERT INTO users (username, phone, network, password_hash, role, created_at) "
                    "VALUES (?, ?, ?, ?, 'member', ?)",
                    (username, phone, network, generate_password_hash(password), now_str()),
                )
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

        # Admin login (by name, network ignored)
        row = db.execute(
            "SELECT * FROM users WHERE role = 'admin' AND LOWER(username) = LOWER(?)",
            (login_input,),
        ).fetchone()

        # Member login (by mobile number + network)
        if row is None:
            row = db.execute(
                "SELECT * FROM users WHERE role = 'member' AND phone = ?",
                (login_input,),
            ).fetchone()
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

    # ----- POST actions (members only) -----
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
            elif db.execute("SELECT 1 FROM contacts WHERE user_id = ? AND phone = ?",
                            (current_user.id, phone)).fetchone():
                flash("You already saved a contact with that number.", "warning")
            else:
                db.execute(
                    "INSERT INTO contacts (user_id, name, phone, network) VALUES (?, ?, ?, ?)",
                    (current_user.id, name, phone, network),
                )
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
            elif db.execute(
                "SELECT 1 FROM users WHERE id != ? AND (phone = ? OR LOWER(username) = LOWER(?))",
                (current_user.id, phone, username),
            ).fetchone():
                flash("That name or mobile number is already used by another account.", "danger")
            else:
                db.execute(
                    "UPDATE users SET username = ?, phone = ?, network = ? WHERE id = ?",
                    (username, phone, network, current_user.id),
                )
                db.commit()
                flash("Profile updated.", "success")

        elif action == "change_password":
            old_pw = request.form.get("old_password", "")
            new_pw = request.form.get("new_password", "")
            row = db.execute("SELECT password_hash FROM users WHERE id = ?",
                             (current_user.id,)).fetchone()
            if not check_password_hash(row["password_hash"], old_pw):
                flash("Current password is incorrect.", "danger")
            elif len(new_pw) < 6:
                flash("New password must be at least 6 characters.", "danger")
            else:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                           (generate_password_hash(new_pw), current_user.id))
                db.commit()
                flash("Password updated.", "success")

        return redirect(url_for("dashboard"))

    # ----- GET -----
    search_query = request.args.get("search", "").strip()
    like = f"%{search_query}%"

    if current_user.role == "admin":
        stats = {
            "total_members": db.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'member'").fetchone()[0],
            "total_contacts": db.execute("SELECT COUNT(*) FROM contacts").fetchone()[0],
        }
        sql = (
            "SELECT u.id, u.username, u.phone, u.network, u.created_at, "
            "COUNT(c.id) AS contacts_count "
            "FROM users u LEFT JOIN contacts c ON c.user_id = u.id "
            "WHERE u.role = 'member' "
        )
        params = []
        if search_query:
            sql += "AND (u.username LIKE ? OR u.phone LIKE ?) "
            params += [like, like]
        sql += "GROUP BY u.id ORDER BY u.id DESC"
        all_members = db.execute(sql, params).fetchall()
        return render_template("dashboard.html", stats=stats, all_members=all_members,
                               search_query=search_query, networks=NETWORKS)

    # member view
    if search_query:
        contacts = db.execute(
            "SELECT * FROM contacts WHERE user_id = ? AND (name LIKE ? OR phone LIKE ?) "
            "ORDER BY name COLLATE NOCASE",
            (current_user.id, like, like),
        ).fetchall()
    else:
        contacts = db.execute(
            "SELECT * FROM contacts WHERE user_id = ? ORDER BY name COLLATE NOCASE",
            (current_user.id,),
        ).fetchall()
    db_user = db.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
    return render_template("dashboard.html", contacts=contacts, db_user=db_user,
                           search_query=search_query, networks=NETWORKS)


# ---------------------------------------------------------------------------
# Contact edit / delete (members)
# ---------------------------------------------------------------------------
@app.route("/contact/<int:id>/update", methods=["GET", "POST"])
@member_required
def update_contact(id):
    db = get_db()
    contact = db.execute("SELECT * FROM contacts WHERE id = ? AND user_id = ?",
                         (id, current_user.id)).fetchone()
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
        elif db.execute("SELECT 1 FROM contacts WHERE user_id = ? AND phone = ? AND id != ?",
                        (current_user.id, phone, id)).fetchone():
            flash("You already saved another contact with that number.", "warning")
        else:
            db.execute("UPDATE contacts SET name = ?, phone = ?, network = ? WHERE id = ?",
                       (name, phone, network, id))
            db.commit()
            flash("Contact updated.", "success")
            return redirect(url_for("dashboard"))
        contact = {"id": id, "name": name, "phone": phone, "network": network}

    return render_template("update.html", contact=contact, networks=NETWORKS)


@app.route("/contact/<int:id>/delete")
@member_required
def delete_contact(id):
    db = get_db()
    db.execute("DELETE FROM contacts WHERE id = ? AND user_id = ?", (id, current_user.id))
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
    user = db.execute("SELECT * FROM users WHERE id = ? AND role = 'member'",
                      (user_id,)).fetchone()
    if user is None:
        flash("Member not found.", "danger")
    else:
        db.execute("DELETE FROM contacts WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        flash(f"Member '{user['username']}' and all their contacts were removed.", "success")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
