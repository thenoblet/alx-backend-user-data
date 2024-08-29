#!/bin/usr/env python3

"""
Data Redaction Utility

This module provides a utility function to redact sensitive information
from log messages or any string containing key-value pairs.

The `filter_datum` function takes a list of fields to redact, a redaction
string, a message, and a separator. It replaces the values associated
with the specified fields in the message with the redaction string.

"""

import re
from typing import List


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """
    Redacts sensitive information from a message.

    This function searches for key-value pairs in the message where the
    key matches one of the specified fields. It replaces the value
    corresponding to these keys with the redaction string.

    Args:
        fields (List[str]): A list of fields (keys) whose values should
        be redacted.
        redaction (str): The string to replace sensitive data with.
        message (str): The input string containing key-value pairs.
        separator (str): The character that separates keys from their values.

    Returns:
        str: The redacted message with sensitive information replaced by
        the redaction string.

    Example:
        >>> message = "name=John Doe;email=johndoe@example.com;password=12345"
        >>> filter_datum(["email", "password"], "***", message, ";")
        'name=John Doe;email=***;password=***'
    """
    return re.sub(
        f'({"|".join(fields)})=[^{separator}]*',
        f'\\1={redaction}', message
    )
