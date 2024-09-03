#!/usr/bin/env python3
"""
API Authentication Module

This module provides the `Auth` class for managing API authentication.
"""

from typing import List, TypeVar, Union
from flask import request


class Auth():
    """
    Auth class to manage API authentication.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if the given path requires authentication.
        """
        if not path or not excluded_paths:
            return True

        slashed_path = self._normalise(path)

        for excluded_path in excluded_paths:
            excluded_path = self._normalise(excluded_path)

            if excluded_path == slashed_path:
                return False

        return True

    def authorization_header(self, request=None) -> Union[str, None]:
        """
        Gets the value of the Authorization header from the request.
        """
        if not request:
            return None

        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Gets the current user based on the request.
        """
        return None

    @staticmethod
    def _normalise(path: str) -> str:
        """
        Normalizes a path by ensuring it ends with a trailing slash.

        Args:
                path (str): The path to normalize.

        Returns:
                str: The normalized path ending with a trailing slash.
        """
        return path if path.endswith("/") else path + "/"
