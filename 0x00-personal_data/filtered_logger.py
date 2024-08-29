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
import os
import logging
from typing import List
import mysql.connector
from mysql.connector.connection import MySQLConnection

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


def get_db() -> MySQLConnection:
    """
    Establishes a connection to a MySQL database using credentials from
    environment variables.

    The function attempts to connect to a MySQL database using the following
    environment variables: 'PERSONAL_DATA_DB_USERNAME',
    'PERSONAL_DATA_DB_PASSWORD', 'PERSONAL_DATA_DB_HOST', and
    'PERSONAL_DATA_DB_NAME'. If any errors occur during the connection attempt,
    an error message is logged.

    Returns:
        MySQLConnection: A MySQL database connection object if successful,
        otherwise None.
    """
    try:
        conn = mysql.connector.connect(
            user=os.environ.get('PERSONAL_DATA_DB_USERNAME', 'root'),
            password=os.environ.get('PERSONAL_DATA_DB_PASSWORD', ""),
            host=os.environ.get('PERSONAL_DATA_DB_HOST', 'localhost'),
            database=os.environ.get('PERSONAL_DATA_DB_NAME'),
        )
        return conn
    except mysql.connector.Error as e:
        logging.error(f"Error connecting to MySQL database: {e}")
        return None
