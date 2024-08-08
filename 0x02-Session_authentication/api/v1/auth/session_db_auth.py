#!/usr/bin/env python3
"""SessionDBAuth class"""

from .session_exp_auth import SessionExpAuth
from os import getenv
from datetime import datetime, timedelta
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """SessionDBAuth class that extends session expiration
    auth with database support."""

    def __init__(self) -> None:
        """Initialize SessionDBAuth with session duration."""
        # Ensure session_duration is an integer
        self.session_duration = int(getenv("SESSION_DURATION", 0))

    def create_session(self, user_id=None):
        """Creates and stores a new instance of UserSession and
        returns the Session ID."""
        session_id = super().create_session(user_id)
        if not session_id:
            return None

        kwargs = {
            "user_id": user_id,
            "session_id": session_id
        }

        # Create a new UserSession instance
        user_session = UserSession(**kwargs)
        # Save the session to the database and file
        user_session.save()
        user_session.save_to_file()

        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Returns the User ID by querying UserSession in the database
        based on session_id."""
        if not session_id:
            return None

        # Load sessions from the file
        UserSession.load_from_file()
        # Search for the session in the database
        user_session = UserSession.search({'session_id': session_id})

        if not user_session:
            return None

        user = user_session[0]

        # Calculate the expiration time
        expired_time = user.created_at + timedelta(
                    seconds=self.session_duration)

        # Check if the session is expired
        if expired_time < datetime.utcnow():
            return None

        return user.user_id

    def destroy_session(self, request=None):
        """Destroys the UserSession based on the Session ID from the
        request cookie."""
        if not request:
            return False

        # Retrieve the session ID from the cookie
        session_id = self.session_cookie(request)

        if not session_id:
            return False

        # Get the user ID associated with the session ID
        user_id = self.user_id_for_session_id(session_id)

        if not user_id:
            return False

        # Find the user session and remove it
        user_session = UserSession.search({"session_id": session_id})

        if user_session:
            # Remove the session from the database
            user_session[0].remove()
            # Save the updated sessions to the file
            UserSession.save_to_file()
            return True

        return False
