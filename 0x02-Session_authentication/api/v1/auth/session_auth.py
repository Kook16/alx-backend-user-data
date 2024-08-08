#!/usr/bin/env python3
"""SessionAuth class"""
from .auth import Auth
from uuid import uuid4
from models.user import User

class SessionAuth(Auth):
    """Creating a new authentication mechanism using session IDs."""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Creates a Session ID for a user_id."""
        if not user_id or not isinstance(user_id, str):
            return None
        # Generate a unique session ID
        session_id = str(uuid4())
        # Map the session ID to the user ID
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Returns a User ID based on a Session ID."""
        if not session_id or not isinstance(session_id, str):
            return None

        # Safely access the dictionary using the session ID
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Returns a User instance based on a cookie value."""
        session_id = self.session_cookie(request)
        # Retrieve the user ID from the session ID
        user_id = self.user_id_by_session_id.__getitem__(session_id)
        # Fetch and return the user instance
        return User.get(user_id)

    def destroy_session(self, request=None):
        """Deletes the user session (logs out the user)."""
        if not request:
            return False

        session_id = self.session_cookie(request)
        if not session_id or session_id not in self.user_id_by_session_id:
            return False

        # Remove the session ID from the mapping
        self.user_id_by_session_id.pop(session_id)
        return True
