#!/usr/bin/env python3
"""
Basic Authentication Module

This module provides the `BasicAuth` class, which is a subclass of the `Auth`
class.
"""
from typing import Tuple, Union, TypeVar
import base64
import binascii

from api.v1.auth.auth import Auth
from models.user import User as DBUser

User = TypeVar("User")


class BasicAuth(Auth):
    """
    BasicAuth class for managing API authentication.

    This class inherits from the `Auth` class. It can be extended in the future
    to implement basic authentication methods, such as verifying user
    credentials through an Authorization header in API requests.
    """
    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """
        Extracts the base64 encoded part of the `Authorization` header.
        """
        if not authorization_header or not isinstance(
            authorization_header, str
        ):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.split(' ', 1)[1]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """
        Decode the Base64 authorization header.
        """
        if not base64_authorization_header or not isinstance(
            base64_authorization_header, str
        ):
            return None

        try:
            return base64.b64decode(
                base64_authorization_header,
                validate=True
            ).decode("utf-8")
        except (binascii.Error, ValueError):
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> Union[Tuple[None, None], Tuple[str, str]]:
        """
        Extracts the username and password from the decoded Base64 string.
        """
        if not decoded_base64_authorization_header or not isinstance(
            decoded_base64_authorization_header, str
        ):
            return None, None

        if ":" not in decoded_base64_authorization_header:
            return None, None

        user_credentials = decoded_base64_authorization_header.split(":", 1)
        if len(user_credentials) != 2:
            return None, None

        username, password = user_credentials
        return username, password

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> Union[User, None]:
        """Return the User instance based on email and password."""
        if not user_email or not isinstance(user_email, str):
            return None

        if not user_pwd or not isinstance(user_pwd, str):
            return None

        try:
            db_user = DBUser.search({"email": user_email})
        except KeyError:
            return None

        if db_user and db_user[0].is_valid_password(user_pwd):
            return db_user[0]

        return None

    def current_user(self, request=None) -> User:
        """Return the current authenticated user."""
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None

        base64_auth_header = self.extract_base64_authorization_header(
            auth_header
        )
        if not base64_auth_header:
            return None

        decoded_base64_auth_header = self.decode_base64_authorization_header(
            base64_auth_header
        )
        if not decoded_base64_auth_header:
            return None

        user_credentials = self.extract_user_credentials(
            decoded_base64_auth_header
        )
        if not user_credentials:
            return None

        user_email, user_pwd = user_credentials
        return self.user_object_from_credentials(user_email, user_pwd)
