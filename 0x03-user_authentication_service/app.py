#!/usr/bin/env python3
"""A Flask app"""

from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

app = Flask(__name__)
app.url_map.strict_slashes = False
AUTH = Auth()


@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """Login a user and create a session."""
    email = request.form.get("email")
    password = request.form.get("password")
    if not email or not password:
        abort(400, description="Missing email or password")

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie("session_id", session_id)
        return response, 200
    else:
        abort(401)


@app.route('/sessions', methods=['DELETE'])
def logout():
    session_id = request.cookies.get('session_id')

    if not session_id:
        abort(403)  # Forbidden if no session ID is provided

    # Get the user associated with the session ID
    user = AUTH.get_user_from_session_id(session_id=session_id)

    if user:
        # Destroy the session
        AUTH.destroy_session(user.id)
        # Redirect to home
        return redirect('/')

    # If user not found, respond with a 403 Forbidden status
    abort(403)


@app.route('/profile', methods=['GET'])
def profile():
    session_id = request.cookies.get('session_id')

    if not session_id:
        abort(403)  # Forbidden if no session ID is provided

    user = AUTH.get_user_from_session_id(session_id)

    if user:
        return jsonify({"email": user.email})

    abort(403)


@app.route('/reset_password', methods=['POST'])
def get_password_reset_token():
    """Handle the password reset request."""
    email = request.form.get('email')
    try:
        token = Auth.get_reset_password_token(email)
    except ValueError:
        abort(404)
    return jsonify({'email': email, 'reset_token': token}), 200


@app.route('/reset_password', methods=['PUT'])
def reset_password():
    """Reset the user password"""
    email = request.form.get('email')
    token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        AUTH.update_password(token, new_password)
    except ValueError:
        abort(403)
    return jsonify({'email': email, "message": "Password updated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
