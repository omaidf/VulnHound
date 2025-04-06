"""
Logging utility for Vulnhound
"""
import logging
import sys
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter to add colors to log messages based on levels
    """
    COLORS = {
        'DEBUG': Fore.BLUE,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        levelname = record.levelname
        message = super().format(record)
        return f"{self.COLORS.get(levelname, '')}{message}{Style.RESET_ALL}"


def setup_logger(verbose=False):
    """
    Set up a logger with colored output
    
    Args:
        verbose: Whether to include DEBUG messages
        
    Returns:
        Logger instance
    """
    logger = logging.getLogger("vulnhound")
    
    # Clear any existing handlers
    if logger.handlers:
        logger.handlers.clear()
    
    # Set log level based on verbose flag
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Create formatters
    detailed_formatter = ColoredFormatter(
        "%(asctime)s - %(levelname)s - %(message)s", 
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    simple_formatter = ColoredFormatter("%(levelname)s: %(message)s")
    
    # Set formatter based on verbose flag
    console_handler.setFormatter(detailed_formatter if verbose else simple_formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    
    return logger
