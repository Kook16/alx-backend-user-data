#!/usr/bin/env python3
"""A Basic Auth class"""
from api.v1.auth.auth import Auth
from typing import TypeVar
import base64
from models.user import User


class BasicAuth(Auth):
    """BasicAuth that inherits from Auth"""

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Returns the Base64 part of the Authorization header for Basic Auth.

        Args:
            authorization_header (str): The authorization header.

        Returns:
            str: The Base64 part of the authorization header, or None if
                 invalid.
        """
        if (not authorization_header or
                type(authorization_header) != str or not
                authorization_header.startswith('Basic ')):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Returns the decoded value of a Base64
        string base64_authorization_header.

        Args:
            base64_authorization_header (str): The Base64 string to decode.

        Returns:
            str: The decoded string, or None if decoding fails.
        """
        if not base64_authorization_header or not isinstance(
                base64_authorization_header, str):
            return None
        try:
            return base64.b64decode(
               base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Returns the user email and password from the Base64 decoded value.

        Args:
            decoded_base64_authorization_header (str): The decoded Base64
                                                       string.

        Returns:
            tuple: The user email and password, or (None, None) if invalid.
        """
        if (not decoded_base64_authorization_header or not isinstance(
                decoded_base64_authorization_header, str) or
                ":" not in decoded_base64_authorization_header):
            return None, None
        return tuple(decoded_base64_authorization_header.split(":", 1))

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        Returns the User instance based on email and password.

        Args:
            user_email (str): The user's email.
            user_pwd (str): The user's password.

        Returns:
            User: The User instance if credentials are valid, None otherwise.
        """
        if not user_email or not user_pwd:
            return None
        users = User.search({'email': user_email})
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the User instance for a request.

        Args:
            request: The request object.

        Returns:
            User: The User instance, or None if not found.
        """
        header_byte = self.authorization_header(request)
        header_to_64 = self.extract_base64_authorization_header(header_byte)
        decoded_header = self.decode_base64_authorization_header(header_to_64)
        header = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(*header)
