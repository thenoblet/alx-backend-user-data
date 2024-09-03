#!/usr/bin/env python3
"""
Basic Authentication Module

This module provides the `BasicAuth` class, which is a subclass of the `Auth`
class.
"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """
    BasicAuth class for managing API authentication.

    This class inherits from the `Auth` class. It can be extended in the future
    to implement basic authentication methods, such as verifying user
    credentials through an Authorization header in API requests.
    """
    pass
