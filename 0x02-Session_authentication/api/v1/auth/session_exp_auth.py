#!/usr/bin/env python3
""""SessionExpAuth Class"""
from .session_auth import SessionAuth
from os import getenv
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """SessionExpAuth class"""
    def __init__(self):
        """initialize method"""
        self.session_duration = int(getenv("SESSION_DURATION", 0))

    def create_session(self, user_id=None):
        """Returns the Session ID created"""
        session_id = super().create_session(user_id)

        if not session_id:
            return None

        session_dictionary = {}
        session_dictionary['user_id'] = user_id
        session_dictionary['created_at'] = datetime.now()
        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """return user_id from the session dictionary"""
        if not session_id or not self.user_id_for_session_id.get(session_id):
            return None

        session_dictionary = self.user_id_for_session_id.get(session_id)

        if session_dictionary is None:
            return None

        if self.session_duration <= 0:
            return session_dictionary.get("user_id")

        if not session_dictionary.get('created_at'):
            return None

        expiration_sec = timedelta(seconds=self.session_duration)

        if (expiration_sec +
                session_dictionary.get('created_at') < datetime.now()):
            return None
        return session_dictionary.get("user_id")
