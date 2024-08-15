#!/usr/bin/env python3
"""user authentication module"""

from bcrypt import hashpw, gensalt, checkpw
from typing import Union
from uuid import uuid4

from sqlalchemy.orm.exc import NoResultFound

from db import DB, User


class Auth:
    """Auth class for the authentication database."""

    def __init__(self):
        """Initializer function"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user with an email and password.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            User: The created User object.

        Raises:
            ValueError: If a user with the same email already exists.
        """
        try:
            # Check if the user already exists
            existing_user = self._db.find_user_by(email=email)
            if existing_user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            # If user does not exist, create a new user
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates login credentials.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            bool: True if login is successful, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return checkpw(password.encode("utf-8"), user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """registers a new user given a new password and email
        """
        try:
            # Find the user by email
            user = self._db.find_user_by(email=email)
            # Generate a new session ID
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return user.session_id

        except NoResultFound:
            # Return None if the user was not found
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Get a user from a session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            User: The User object corresponding to the session ID, or
            None if no user is found.
        """
        if not session_id:
            return None

        try:
            # Query the user with the given session_id
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            # If no user is found, return None
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy the session for a given user ID by setting the session ID
        to None.

        Args:
            user_id (int): The ID of the user whose session is to be destroyed.

        Returns:
            None
        """
        self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Generate a reset password token for a user with the given email.

        Args:
            email (str): The user's email.

        Returns:
            str: The generated reset token.

        Raises:
            ValueError: If the user does not exist.
        """
        try:
            # Find the user by email
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        # Generate a new UUID token
        reset_token = _generate_uuid()
        # Update the user's reset_token field
        self._db.update_user(email=email, reset_token=reset_token)

        return reset_token

    def update_password(
            self, reset_token: str, password: str) -> None:
        """Update the user's password using a reset token.

        Args:
            reset_token (str): The user's reset token.
            password (str): The new password.

        Raises:
            ValueError: If the user with the given reset token does not exist.
        """
        try:
            # Find the user by reset token
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        # Hash the new password
        hashed_password = _hash_password(password)

        # Update the user's hashed_password and reset_token
        self._db.update_user(
            email=user.email,
            hashed_password=hashed_password,
            reset_token=None
        )


def _hash_password(password: str) -> bytes:
    """Hash a password using bcrypt and return the hashed password."""
    return hashpw(password.encode('utf-8'), gensalt())


def _generate_uuid() -> str:
    """
    hashes raw password data with bcrypt
    """
    return str(uuid4())
