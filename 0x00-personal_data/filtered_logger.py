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
    """ Redacts sensitive information from a message. """
    return re.sub(
        f'({"|".join(fields)})=[^{separator}]*',
        f'\\1={redaction}', message
    )
