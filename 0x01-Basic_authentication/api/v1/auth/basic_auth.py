#!/usr/bin/env python3
"""
Basic Authentication Module

This module provides the `BasicAuth` class, which is a subclass of the `Auth`
class.
"""
from api.v1.auth.auth import Auth
import base64
import binascii


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
