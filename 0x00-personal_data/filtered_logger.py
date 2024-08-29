#!/usr/bin/env python3

"""
Data Redaction Utility

This module provides a utility function to redact sensitive information
from log messages or any string containing key-value pairs.

The `filter_datum` function takes a list of fields to redact, a redaction
string, a message, and a separator. It replaces the values associated
with the specified fields in the message with the redaction string.

The `RedactingFormatter` class extends the `logging.Formatter` class to
redact specified fields in log messages.

The `get_logger` function sets up a logger with the `RedactingFormatter`
to ensure sensitive information is not logged.

"""

import re
import logging
from typing import List

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


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

    def __init__(self, fields: List[str]):
        """Initialize logger."""
        super(RedactingFormatter, self).__init__(fmt=self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Format the log record, redacting sensitive information."""
        log_message = super(RedactingFormatter, self).format(record)
        return filter_datum(
            self.fields, self.REDACTION, log_message, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Sets up and returns a logger configured to redact sensitive information.

    The logger is set to the INFO level and uses a stream handler with the
    `RedactingFormatter` to ensure that any log messages containing sensitive
    information are redacted before being output.

    Returns:
        logging.Logger: A configured logger instance.
    """
    logger = logging.getLogger(name='user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(fields=list(PII_FIELDS)))
    logger.addHandler(stream_handler)

    return logger
