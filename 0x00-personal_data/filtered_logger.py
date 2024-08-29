#!/usr/bin/env python3

"""
Data Redaction Utility

This module provides a utility function to redact sensitive information
from log messages or any string containing key-value pairs.

The `filter_datum` function takes a list of fields to redact, a redaction
string, a message, and a separator. It replaces the values associated
with the specified fields in the message with the redaction string.

"""

import re
import logging
from typing import List


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """ Redacts sensitive information from a message."""
    for field in fields:
        pattern = rf'{field}=([^{separator}]+)'
        message = re.sub(pattern, f'{field}={redaction}', message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List):
        """Initialize logger."""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Redact/filter the log message using filter_datum function."""
        log_message = super(RedactingFormatter, self).format(record)
        return filter_datum(
            self.fields, self.REDACTION, log_message, self.SEPARATOR
        )
