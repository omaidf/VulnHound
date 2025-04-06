#!/usr/bin/env python3
"""
Vulnhound - Security Vulnerability Scanner for Code Repositories

A command-line tool that combines AI-powered and pattern-based approaches
to detect security vulnerabilities in code repositories across multiple languages.
"""
import os
import sys
import argparse
import json
import time
from pathlib import Path
import colorama

from core.scanner import Scanner, ScannerError
from core.environment import check_environment, EnvironmentError
from utils.logger import setup_logger
from output.report_generator import generate_report


def parse_arguments():
    """
    Parse command line arguments with detailed help information
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Vulnhound - Security Vulnerability Scanner for Code Repositories",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "repository",
        help="Path to the code repository to scan (absolute or relative path)"
    )
    
    parser.add_argument(
        "--extensions",
        help="Comma-separated list of file extensions to scan (e.g., py,js,java)",
        default="py,js,java,go,php,rb,c,cpp,cs"
    )
    
    parser.add_argument(
        "--exclude-dirs",
        help="Comma-separated list of directories to exclude (e.g., tests,docs)",
        default=".git,node_modules,venv,__pycache__,.venv,dist,build"
    )
    
    parser.add_argument(
        "--output-format",
        choices=["json", "html", "console"],
        default="console",
        help="Output format for the vulnerability report"
    )
    
    parser.add_argument(
        "--output-file",
        help="Path to save the output report (not needed for console output)"
    )

    parser.add_argument(
        "--max-workers",
        type=int,
        help="Maximum number of worker threads for parallel scanning"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--skip-environment-check",
        action="store_true",
        help="Skip environment verification"
    )
    
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI-based detection (faster but less accurate)"
    )
    
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable ASCII art banner"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Vulnhound 0.1.0",
        help="Show version information and exit"
    )
    
    return parser.parse_args()


def main():
    """
    Main entry point for Vulnhound
    
    This function:
    1. Parses command line arguments
    2. Sets up logging
    3. Validates the environment
    4. Initializes and runs the scanner
    5. Generates the vulnerability report
    
    Returns:
        int: Exit code (0 for success, 1 for scan with vulnerabilities, 2 for error)
    """
    start_time = time.time()
    
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Banner display
        if not args.no_banner:
            banner = r"""
 __      __    _       _                         _ 
 \ \    / /   | |     | |                       | |
  \ \  / /   _| |_ __ | |__   ___  _   _ _ __   | |
   \ \/ / | | | | '_ \| '_ \ / _ \| | | | '_ \  | |
    \  /| |_| | | | | | | | | (_) | |_| | | | | |_|
     \/  \__,_|_|_| |_|_| |_|\___/ \__,_|_| |_| (_)
                                                   
        AI-enhanced Security Vulnerability Scanner
        """
            print(colorama.Fore.CYAN + banner + colorama.Style.RESET_ALL)
        
        # Setup logging
        logger = setup_logger(verbose=args.verbose)
        logger.info("Starting Vulnhound security scan")
        
        # Check environment unless skipped
        if not args.skip_environment_check:
            try:
                if not check_environment(skip_ai=args.no_ai):
                    logger.error("Environment check failed. Please install required dependencies.")
                    return 2
            except EnvironmentError as e:
                logger.error(f"Environment error: {str(e)}")
                return 2
        
        # Validate repository path
        repo_path = Path(args.repository).resolve()
        if not repo_path.exists():
            logger.error(f"Repository path does not exist: {repo_path}")
            return 2
        if not repo_path.is_dir():
            logger.error(f"Repository path is not a directory: {repo_path}")
            return 2
        
        # Parse extensions and excluded directories
        extensions = [ext.strip() for ext in args.extensions.split(",")]
        exclude_dirs = set(dir.strip() for dir in args.exclude_dirs.split(","))
        
        # Initialize scanner
        try:
            scanner = Scanner(
                repo_path, 
                extensions, 
                logger,
                exclude_dirs=exclude_dirs,
                max_workers=args.max_workers
            )
            
            # Run the scan
            vulnerabilities = scanner.scan()
            
            # Generate and output report
            if vulnerabilities:
                logger.warning(f"Found {len(vulnerabilities)} potential security vulnerabilities")
                
                if args.output_format == "console":
                    generate_report(vulnerabilities, "console", None, logger)
                else:
                    if not args.output_file:
                        logger.error(f"{args.output_format} output format requires --output-file parameter")
                        return 2
                    
                    output_path = Path(args.output_file)
                    # Create parent directories if they don't exist
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    generate_report(vulnerabilities, args.output_format, str(output_path), logger)
                    logger.info(f"Report saved to {output_path}")
                
                # Exit with status code 1 if vulnerabilities were found (for CI/CD pipelines)
                return 1
            else:
                logger.info("No security vulnerabilities detected")
                return 0
                
        except ScannerError as e:
            logger.error(f"Scanning error: {str(e)}")
            return 2
            
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 2
    except Exception as e:
        logger = setup_logger(verbose=True)  # Ensure we have a logger even if it failed earlier
        logger.error(f"Unexpected error: {str(e)}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        return 2
    finally:
        elapsed_time = time.time() - start_time
        logger = setup_logger(verbose=False)  # Ensure we have a logger even if it failed earlier
        logger.info(f"Total execution time: {elapsed_time:.2f} seconds")


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
