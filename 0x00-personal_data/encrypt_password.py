#!/usr/bin/env python3

"""
Password Hashing Utility

This script provides a utility function to hash passwords using the
bcrypt algorithm. It ensures that passwords are securely hashed before
being stored or transmitted.

The `hash_password` function takes a plain text password, hashes it
using bcrypt, and returns the hashed password.

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
