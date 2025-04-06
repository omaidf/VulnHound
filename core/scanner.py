"""
Core scanner module for Vulnhound
"""
import os
import time
import traceback
from pathlib import Path
from typing import List, Dict, Any, Set, Optional
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.code_parser import CodeParser
from models.vulnerability import Vulnerability, CodeLocation
from models.patterns import VULNERABILITY_PATTERNS
from models.ai_detector import AIDetector


class ScannerError(Exception):
    """Custom exception for scanner errors"""
    pass


class Scanner:
    """
    Main scanner class that processes code repositories and detects vulnerabilities.
    
    This class coordinates the scanning process, including file collection,
    code parsing, pattern matching, and AI-based vulnerability detection.
    It supports parallel processing to improve performance on multi-core systems.
    """
    
    # Default directories to exclude from scanning
    DEFAULT_EXCLUDE_DIRS = {
        '.git', 'node_modules', 'venv', '.venv', '__pycache__', 
        'build', 'dist', '.idea', '.vscode', 'vendor', 'target',
        'bin', 'obj', 'packages', 'logs', 'tmp'
    }
    
    def __init__(self, 
                 repo_path: Path, 
                 extensions: List[str], 
                 logger,
                 exclude_dirs: Optional[Set[str]] = None,
                 max_workers: int = None):
        """
        Initialize the scanner with target repository and file extensions
        
        Args:
            repo_path: Path to the code repository
            extensions: List of file extensions to scan
            logger: Logger instance
            exclude_dirs: Optional set of directory names to exclude from scanning
            max_workers: Maximum number of worker threads for parallel scanning
                        (defaults to min(32, os.cpu_count() + 4))
        
        Raises:
            ScannerError: If repository path does not exist or is not a directory
        """
        # Validate repository path
        if not repo_path.exists():
            raise ScannerError(f"Repository path does not exist: {repo_path}")
        if not repo_path.is_dir():
            raise ScannerError(f"Repository path is not a directory: {repo_path}")
            
        self.repo_path = repo_path
        self.extensions = extensions
        self.logger = logger
        self.exclude_dirs = exclude_dirs or self.DEFAULT_EXCLUDE_DIRS
        self.max_workers = max_workers
        
        # Initialize parsers and detectors
        self.code_parser = CodeParser(logger)
        self.ai_detector = AIDetector(logger)
        
    def scan(self) -> List[Vulnerability]:
        """
        Scan the repository for vulnerabilities
        
        This method orchestrates the entire scanning process:
        1. Collect all target files
        2. Scan files in parallel
        3. Aggregate and return all detected vulnerabilities
        
        Returns:
            List of detected vulnerabilities
            
        Raises:
            ScannerError: If a critical error occurs during scanning
        """
        start_time = time.time()
        self.logger.info(f"Starting security scan of repository: {self.repo_path}")
        self.logger.info(f"Looking for file extensions: {', '.join(self.extensions)}")
        
        try:
            # Collect all target files
            files = self._collect_files()
            if not files:
                self.logger.warning(f"No matching files found in {self.repo_path}")
                return []
                
            self.logger.info(f"Found {len(files)} files to scan")
            
            # Scan files in parallel
            vulnerabilities = []
            
            # Use a thread pool to parallelize file scanning
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all files for scanning
                future_to_file = {
                    executor.submit(self._scan_file, file_path): file_path 
                    for file_path in files
                }
                
                # Process results as they complete
                completed = 0
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    completed += 1
                    
                    # Log progress periodically
                    if completed % 50 == 0 or completed == len(files):
                        self.logger.info(f"Progress: {completed}/{len(files)} files scanned ({completed*100//len(files)}%)")
                    
                    try:
                        file_vulnerabilities = future.result()
                        if file_vulnerabilities:
                            vulnerabilities.extend(file_vulnerabilities)
                            self.logger.info(f"Found {len(file_vulnerabilities)} potential vulnerabilities in {file_path.relative_to(self.repo_path)}")
                    except Exception as e:
                        self.logger.error(f"Error scanning {file_path}: {str(e)}")
                        if self.logger.level <= 10:  # DEBUG level or lower
                            self.logger.debug(f"Traceback: {traceback.format_exc()}")
            
            elapsed_time = time.time() - start_time
            self.logger.info(f"Scanning completed in {elapsed_time:.2f} seconds")
            self.logger.info(f"Found {len(vulnerabilities)} potential security vulnerabilities in total")
            
            return vulnerabilities
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            return []
        except Exception as e:
            error_msg = f"Critical error during scanning: {str(e)}"
            self.logger.error(error_msg)
            self.logger.debug(f"Traceback: {traceback.format_exc()}")
            raise ScannerError(error_msg) from e
    
    def _collect_files(self) -> List[Path]:
        """
        Collect all files with target extensions from the repository
        
        Traverses the repository directory structure, applying filters for:
        - File extensions
        - Excluded directories
        
        Returns:
            List of file paths to scan
        """
        files = []
        try:
            for ext in self.extensions:
                # Normalize extension (remove dot if present)
                ext = ext.lstrip('.')
                
                # Use '**/*' to find files recursively
                pattern = f"**/*.{ext}"
                ext_files = list(self.repo_path.glob(pattern))
                files.extend(ext_files)
                
            # Filter out files in directories to ignore
            filtered_files = []
            for file_path in files:
                # Convert to relative path for easier directory checking
                rel_path = file_path.relative_to(self.repo_path)
                parts = rel_path.parts
                
                # Skip if any parent directory is in exclude_dirs
                if any(part in self.exclude_dirs for part in parts):
                    continue
                    
                filtered_files.append(file_path)
                
            return filtered_files
            
        except Exception as e:
            self.logger.error(f"Error collecting files: {str(e)}")
            return []
    
    def _scan_file(self, file_path: Path) -> List[Vulnerability]:
        """
        Scan a single file for vulnerabilities
        
        This method:
        1. Reads and parses the file
        2. Applies pattern-based detection
        3. Applies AI-based detection if available
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of vulnerabilities found in the file
            
        Raises:
            Exception: If an error occurs during file scanning
        """
        self.logger.debug(f"Scanning file: {file_path}")
        vulnerabilities = []
        
        try:
            # Verify file exists and is readable
            if not file_path.exists():
                self.logger.warning(f"File does not exist: {file_path}")
                return []
                
            if not os.access(file_path, os.R_OK):
                self.logger.warning(f"File is not readable: {file_path}")
                return []
                
            # Read file content with error handling for encoding issues
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                # Try with a more forgiving encoding
                try:
                    with open(file_path, 'r', encoding='latin-1') as f:
                        content = f.read()
                    self.logger.debug(f"File {file_path} read with latin-1 encoding")
                except Exception as e:
                    self.logger.warning(f"Could not read file {file_path}: {str(e)}")
                    return []
            
            # Skip empty files
            if not content.strip():
                return []
                
            # Parse code to AST if possible
            ast = self.code_parser.parse(file_path, content)
            
            # Pattern-based detection (always runs)
            pattern_vulnerabilities = self._detect_pattern_vulnerabilities(file_path, content, ast)
            vulnerabilities.extend(pattern_vulnerabilities)
            
            # AI-based detection (runs if models are available)
            try:
                ai_vulnerabilities = self.ai_detector.detect_vulnerabilities(file_path, content, ast)
                vulnerabilities.extend(ai_vulnerabilities)
            except Exception as e:
                self.logger.warning(f"AI-based detection failed for {file_path}: {str(e)}")
                # Continue with pattern-based results only
            
        except MemoryError:
            self.logger.error(f"Memory error while processing {file_path}. File may be too large.")
            return []
        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {str(e)}")
            if self.logger.level <= 10:  # DEBUG level or lower
                self.logger.debug(f"Traceback: {traceback.format_exc()}")
            raise  # Re-raise to be handled by the scanner
        
        return vulnerabilities
    
    def _detect_pattern_vulnerabilities(self, file_path: Path, content: str, ast) -> List[Vulnerability]:
        """
        Detect vulnerabilities using pattern matching
        
        Uses regex and AST patterns to identify potential security issues.
        
        Args:
            file_path: Path to the file
            content: File content
            ast: Abstract Syntax Tree of the file (if available)
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        file_extension = file_path.suffix.lstrip('.')
        
        # Get patterns for this file type
        patterns = []
        
        # Add language-specific patterns
        if file_extension in VULNERABILITY_PATTERNS:
            patterns.extend(VULNERABILITY_PATTERNS[file_extension])
            
        # Add common patterns that apply to all languages
        if 'common' in VULNERABILITY_PATTERNS:
            patterns.extend(VULNERABILITY_PATTERNS['common'])
            
        if not patterns:
            return []
        
        # Check for each pattern
        for pattern in patterns:
            try:
                # Find matches using the pattern
                findings = pattern.find_in_code(content, ast)
                
                # Update the file path in each finding
                for finding in findings:
                    finding.location.file_path = file_path
                    
                vulnerabilities.extend(findings)
            except Exception as e:
                self.logger.debug(f"Error applying pattern {pattern.name} to {file_path}: {str(e)}")
        
        return vulnerabilities
