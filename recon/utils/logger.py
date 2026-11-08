'''
Logging setup.
'''

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

LOGGER_NAME: str = "recon"


def setup_logging(verbose: bool) -> logging.Logger:
    '''
    Configure Rich logging to stderr; the recon logger is WARNING unless verbose.
    Parameters:
        verbose (bool): Enable DEBUG logging.
    Returns:
        logging.Logger: The root 'recon' logger.
    '''
    handler = RichHandler(
        console=Console(stderr=True),
        show_path=False,
        rich_tracebacks=verbose,
        markup=False,
    )
    logging.basicConfig(
        level=logging.WARNING,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[handler],
        force=True,
    )
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    return logger


def get_logger(name: str) -> logging.Logger:
    '''
    Return a child logger under 'recon'.
    Parameters:
        name (str): Child logger name.
    Returns:
        logging.Logger: The logger.
    '''
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
