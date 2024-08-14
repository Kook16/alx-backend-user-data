#!/usr/bin/env python3
"""End-to-end integration test
"""
from auth import Auth
import requests

EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"
BASE_URL = "http://127.0.0.1:5000"


def register_user(email: str, password: str) -> None:
    """assert correct response to register user with email and password"""
    pass


def log_in_wrong_password(email: str, password: str) -> None:
    """ assert correct response to register user with
        email and incorrect password."""
    pass


def profile_unlogged() -> None:
    """ assert correct response to the
        profile endpoint without logging in: 403."""
    pass


def log_in(email: str, password: str) -> str:
    """
    assert correct response to
    logging email and password
    returns session ID"""
    return None


def profile_logged(session_id: str) -> None:
    """
    assert correct response to the profile endpoint
    with a valid session ID.
    """
    pass


def log_out(session_id: str) -> None:
    """
    assert correct response to the log out user
    with a specified session ID.
    """
    pass


def reset_password_token(email: str) -> str:
    """
    assert correct response to
    Requests a password reset token for the specified email.
    """
    return None


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """
    assert correct response to
    update the password for user email
    """
    pass


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
