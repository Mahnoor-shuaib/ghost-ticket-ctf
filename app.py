import os
import base64
import secrets
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, abort, flash)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Flag: 24 characters total, change via the FLAG environment variable if you like.
FLAG = os.environ.get("FLAG", "CGS{1d0r_chain_n0t_s4fe}")

# ---------------------------------------------------------------------------
# In-memory data (resets when the server restarts; that is fine for a CTF)
# ---------------------------------------------------------------------------
USERS = {
    # The admin password is random, so players cannot log in as admin.
    "admin": {"hash": generate_password_hash(secrets.token_hex(16)), "role": "admin"},
    "maria": {"hash": generate_password_hash(secrets.token_hex(16)), "role": "user"},
    "dev_tom": {"hash": generate_password_hash(secrets.token_hex(16)), "role": "user"},
    "sana": {"hash": generate_password_hash(secrets.token_hex(16)), "role": "user"},
}

TICKETS = {
    1: {"owner": "admin", "title": "Support portal v2 rollout",
        "body": ("Team, the portal moved to v2 this week. Internal notes are no longer "
                 "kept in tickets; they live in the staff panel now. Panel wiring is in "
                 "the dashboard script, so check /static/app.js if you forget the path. "
                 "Do not share outside the team.")},
    2: {"owner": "maria", "title": "Cannot reset my password",
        "body": "The reset email never arrives. I tried twice with the same address."},
    3: {"owner": "dev_tom", "title": "Dark mode request",
        "body": "Any plan for a dark theme? Late night support shifts are rough on the eyes."},
    4: {"owner": "sana", "title": "Invoice #2291 is wrong",
        "body": "I was charged twice for October. Please check and refund one payment."},
}
NEXT_ID = [5]

ADMIN_NOTES = [
    "Rotate the staff panel password every 30 days.",
    "Escalation contact for billing: finance desk, ext. 214.",
    "Audit key: " + FLAG,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def encode_id(n: int) -> str:
    return base64.b64encode(f"ticket-{n}".encode()).decode()


def decode_id(token: str):
    try:
        raw = base64.b64decode(token.encode(), validate=True).decode()
        prefix, num = raw.split("-", 1)
        if prefix != "ticket":
            return None
        return int(num)
    except Exception:
        return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "login required"}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def create_ticket(owner, title, body):
    tid = NEXT_ID[0]
    NEXT_ID[0] += 1
    TICKETS[tid] = {"owner": owner, "title": title, "body": body}
    return tid


app.jinja_env.globals["encode_id"] = encode_id


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if not (3 <= len(username) <= 20) or not username.replace("_", "").isalnum():
            flash("Username must be 3-20 characters: letters, numbers, underscore.")
        elif len(password) < 4:
            flash("Password must be at least 4 characters.")
        elif username in USERS:
            flash("That username is taken. Pick another one.")
        else:
            USERS[username] = {"hash": generate_password_hash(password), "role": "user"}
            create_ticket(username, "Welcome to the support portal",
                          "Thanks for signing up. Open a ticket any time you need help.")
            flash("Account created. You can log in now.")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and check_password_hash(user["hash"], password):
            session["user"] = username
            return redirect(url_for("dashboard"))
        flash("Wrong username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    me = session["user"]
    mine = [(tid, t) for tid, t in TICKETS.items() if t["owner"] == me]
    return render_template("dashboard.html", user=me, tickets=mine)


@app.route("/ticket/new", methods=["POST"])
@login_required
def new_ticket():
    title = request.form.get("title", "").strip()[:80]
    body = request.form.get("body", "").strip()[:500]
    if not title or not body:
        flash("A ticket needs both a title and a description.")
        return redirect(url_for("dashboard"))
    tid = create_ticket(session["user"], title, body)
    return redirect(url_for("view_ticket", token=encode_id(tid)))


# VULNERABILITY 1: the ticket is returned to any logged-in user.
# There is no check that ticket["owner"] == session["user"].
@app.route("/ticket/<token>")
@login_required
def view_ticket(token):
    tid = decode_id(token)
    ticket = TICKETS.get(tid) if tid is not None else None
    if ticket is None:
        abort(404)
    return render_template("ticket.html", ticket=ticket, tid=tid)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.route("/api/me")
@login_required
def api_me():
    me = session["user"]
    return jsonify({"username": me, "role": USERS[me]["role"]})


# VULNERABILITY 2: only login is checked, the role is never verified.
# The admin button is hidden in the frontend, but the server does not enforce it.
@app.route("/api/admin/notes")
@login_required
def admin_notes():
    return jsonify({"notes": ADMIN_NOTES})


@app.errorhandler(404)
def not_found(_):
    return render_template("404.html"), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
