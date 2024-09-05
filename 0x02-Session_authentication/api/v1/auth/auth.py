#!/usr/bin/env python3

"""This module implements base class for Authentication mechanisms."""

import os
from typing import List, TypeVar, Union

User = TypeVar("User")


class Auth:
    """Auth class to manage the API authentication."""

    @staticmethod
    def require_auth(path: str, excluded_paths: List[str]) -> bool:
        """Require authentication for API paths except for excluded paths."""
        if not path or not excluded_paths:
            return True

        path = path.rstrip("/") + "/"

        for exc_path in excluded_paths:
            # perform a simple a regex to accept paths matching the pattern
            if path.startswith(exc_path.rstrip("*")):
                return False

        return path not in excluded_paths

    @staticmethod
    def authorization_header(request=None) -> Union[str, None]:
        """Return the value of the Authorization header."""
        if not request:
            return None

        return request.headers.get("Authorization")

    def current_user(self, request=None) -> User:
        """Return the current user."""
        return None

    @staticmethod
    def session_cookie(request=None) -> Union[str, None]:
        """Return the value of the session cookie.

        The cookie name must be saved in an environment variable named
        `SESSION_NAME`.
        """
        if not request:
            return None

        return request.cookies.get(os.environ.get("SESSION_NAME"))
