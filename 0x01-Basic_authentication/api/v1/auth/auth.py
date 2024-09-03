#!/usr/bin/env python3
"""
API Authentication Module

This module provides the `Auth` class for managing API authentication.
"""

from typing import List, TypeVar
from flask import request


class Auth():
    """
    Auth class to manage API authentication.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if the given path requires authentication.
        """
        return False

    def authorization_header(self, request=None) -> str:
        """
        Gets the value of the Authorization header from the request.
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Gets the current user based on the request.
        """
        return None
