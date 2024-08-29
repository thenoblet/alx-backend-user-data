#!/usr/bin/env python3

"""
Password Hashing and Validation Utility

This script provides utility functions to hash passwords and verify
hashed passwords using the bcrypt algorithm. It ensures that passwords
are securely hashed before being stored or transmitted and allows for
the validation of passwords against their hashes.

The `hash_password` function hashes a plain text password using bcrypt.

The `is_valid` function checks if a given plain text password matches
a hashed password.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    This function takes a plain text password as input, encodes it to
    bytes, generates a salt using `bcrypt.gensalt()`, and then hashes
    the password using `bcrypt.hashpw()`.

    Args:
        password (str): The plain text password to hash.

    Returns:
        bytes: The hashed password in bytes format, which includes the salt.
    """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a hashed password.

    This function takes a hashed password and a plain text password,
    encodes the plain text password to bytes, and uses `bcrypt.checkpw()`
    to check if the provided password matches the hashed password.

    Args:
        hashed_password (bytes): The hashed password to validate against.
        password (str): The plain text password to check.

    Returns:
        bool: True if the password matches the hashed password,
        False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
