# Ghost Ticket: Solution Writeup

**Category:** Web  
**Difficulty:** Medium  
**Vulnerability:** Broken Access Control (IDOR + missing function-level authorization)  
**Flag:** `CGS{1d0r_chain_n0t_s4fe}`

> Organiser document. Do not share with participants.

---

## Overview

Ghost Ticket is a support portal built with Flask. Users register, log in and open tickets.
The challenge is a two-stage chain:

1. **Horizontal access (IDOR):** a user can read other users' tickets because the server never checks who owns a ticket.
2. **Vertical access (missing role check):** a hidden admin API only checks that the caller is logged in, not that the caller is an admin.

---

## Solution

### Step 1: Register and log in

Create any account at `/register`, then log in. The dashboard shows one ticket, "Welcome to the support portal".

### Step 2: Inspect the ticket URL

Open the ticket. The URL looks like this:

```
/ticket/dGlja2V0LTU=
```

The ID is not random. It is base64. Decoding it:

```
$ echo dGlja2V0LTU= | base64 -d
ticket-5
```

So ticket IDs are just `ticket-<number>`, encoded. They are predictable.

### Step 3: Read someone else's ticket (IDOR)

Encode a different number, for example `ticket-1`:

```
$ echo -n "ticket-1" | base64
dGlja2V0LTE=
```

Open `/ticket/dGlja2V0LTE=`. The server returns the admin's ticket. It never compares the ticket owner with the logged-in user.

The ticket says the staff panel is wired up in the dashboard script, `/static/app.js`.

### Step 4: Read the dashboard script

Open `/static/app.js`. It contains:

```js
const STAFF_NOTES_ENDPOINT = "/api/admin/notes";
```

The script only shows the "Open staff notes" button when `/api/me` reports `role === "admin"`. That is a client-side check, which players can ignore.

### Step 5: Call the admin endpoint directly

While logged in as the normal user, open:

```
/api/admin/notes
```

The server only checks that a session exists. It does not check the role, so it returns the notes:

```json
{"notes": ["Rotate the staff panel password every 30 days.",
           "Escalation contact for billing: finance desk, ext. 214.",
           "Audit key: CGS{1d0r_chain_n0t_s4fe}"]}
```

**Flag:** `CGS{1d0r_chain_n0t_s4fe}`

---

## Solve flow at a glance

```
Register -> Login -> Open own ticket -> Notice base64 ID -> Decode
-> Encode ticket-1 -> Open admin's ticket -> Find /static/app.js
-> Find /api/admin/notes -> Request it as a normal user -> Flag
```

---

## Root causes (the vulnerable code)

**1. No ownership check on tickets (`app.py`):**

```python
@app.route("/ticket/<token>")
@login_required
def view_ticket(token):
    tid = decode_id(token)
    ticket = TICKETS.get(tid) if tid is not None else None
    if ticket is None:
        abort(404)
    return render_template("ticket.html", ticket=ticket, tid=tid)
```

**2. No role check on the admin endpoint (`app.py`):**

```python
@app.route("/api/admin/notes")
@login_required
def admin_notes():
    return jsonify({"notes": ADMIN_NOTES})
```

**3. Authorization only in the frontend (`static/app.js`):** the admin button is hidden for non-admins, but hiding a button does not protect the endpoint behind it.

---

## How to fix it

```python
@app.route("/ticket/<token>")
@login_required
def view_ticket(token):
    tid = decode_id(token)
    ticket = TICKETS.get(tid) if tid is not None else None
    # Return 404 for both "missing" and "not yours" so IDs cannot be probed.
    if ticket is None or ticket["owner"] != session["user"]:
        abort(404)
    return render_template("ticket.html", ticket=ticket, tid=tid)


@app.route("/api/admin/notes")
@login_required
def admin_notes():
    if USERS[session["user"]]["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"notes": ADMIN_NOTES})
```

Lessons:

- Check **object ownership** on the server for every request that returns a user's data.
- Check **role/permission** on every privileged endpoint. Never rely on hidden buttons.
- Encoding an ID (base64) is not protection. Use real authorization, and unpredictable IDs only as an extra layer.



