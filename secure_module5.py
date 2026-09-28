#Gentry Bayer, Secure Coding Project   
# Secure Coding Project - Password Hasher Implementation
# September 27, 2026 

import hashlib, secrets
from datetime import datetime, timedelta, timezone
from flask import request, abort
from argon2 import PasswordHasher

ph = PasswordHasher()
TOKEN_TTL = timedelta(minutes=15)
GENERIC = ("If that account exists, a reset link has been sent.", 200)

def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

# Step 1: request a reset. Proves control of the mailbox, not just knowledge of the email.
@app.route('/reset-password/request', methods=['POST'])
@limiter.limit("5 per hour")                       # e.g. Flask-Limiter
def request_reset():
    email = request.form.get('email', '').strip().lower()
    user = User.query.filter_by(email=email).first()
    if user:
        token = secrets.token_urlsafe(32)          # 256-bit unguessable token
        user.reset_token_hash = _digest(token)     # store only the hash
        user.reset_expires = datetime.now(timezone.utc) + TOKEN_TTL
        db.session.commit()
        send_email(user.email, f"https://example.com/reset?token={token}")
    return GENERIC                                 # identical response: no user enumeration

# Step 2: redeem the token and set the new password
@app.route('/reset-password/confirm', methods=['POST'])
@limiter.limit("10 per hour")
def confirm_reset():
    token = request.form.get('token', '')
    new_password = request.form.get('new_password', '')
    if not (12 <= len(new_password) <= 128):
        abort(400, "Password must be 12-128 characters")

    user = User.query.filter_by(reset_token_hash=_digest(token)).first()
    if (user is None or user.reset_expires is None
            or user.reset_expires < datetime.now(timezone.utc)):
        abort(400, "Invalid or expired token")

    user.password_hash = ph.hash(new_password)     # hashed, never plaintext
    user.reset_token_hash = None                   # single use
    user.reset_expires = None
    invalidate_all_sessions(user)                  # log out existing sessions
    db.session.commit()
    notify_password_changed(user.email)            # alert the real owner
    return "Password updated", 200
