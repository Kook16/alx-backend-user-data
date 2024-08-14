#!/usr/bin/env python3
"""A Flask app"""


from flask import Flask, jsonify, request, abort
from auth import Auth

app = Flask(__name__)
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

    @app.route('/reset_password', methods=['PUT'])
    def update_password():
        """Handle the password reset request."""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(
                user.id, hashed_password=hashed_password, reset_token=None)
            return None
        except NoResultFound:
            raise ValueError


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
