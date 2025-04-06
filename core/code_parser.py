import ast
import os
from pathlib import Path
from typing import Optional, Dict, Any, Union
from tree_sitter import Language, Parser

# Comprehensive mapping of file extensions to tree-sitter grammar repositories
SUPPORTED_LANGUAGES = {
    'py': 'python',
    'js': 'javascript',
    'jsx': 'javascript',
    'ts': 'typescript',
    'tsx': 'typescript',
    'java': 'java',
    'go': 'go',
    'rb': 'ruby',
    'php': 'php',
    'c': 'c',
    'cpp': 'cpp',
    'h': 'c',
    'hpp': 'cpp',
    'cs': 'c_sharp'
}


class CodeParserError(Exception):
    """Custom exception for code parsing errors"""
    pass


class CodeParser:
    """
    Parses code files using tree-sitter and AST analysis for vulnerability detection.
    
    This class provides functionality to parse code into abstract syntax trees (ASTs)
    which can then be used for semantic analysis of security vulnerabilities.
    It supports multiple languages through the tree-sitter parser library.
    """
    
    def __init__(self, logger):
        """
        Initialize code parser with language-specific parsers
        
        Args:
            logger: Logger instance for tracking parser operations
        """
        self.logger = logger
        self.parsers = {}
        self._load_parsers()

    def _load_parsers(self):
        """
        Load tree-sitter parsers for all supported languages
        
        Creates necessary directories and attempts to load each language parser.
        Gracefully handles missing parsers by logging warnings.
        """
        # Ensure build directory exists
        build_dir = Path('build')
        build_dir.mkdir(exist_ok=True)
        
        # Ensure vendor directory exists
        vendor_dir = Path('vendor')
        vendor_dir.mkdir(exist_ok=True)
        
        for lang, grammar in SUPPORTED_LANGUAGES.items():
            try:
                # Skip already loaded parsers to avoid duplication
                if lang in self.parsers:
                    continue
                    
                # Check if parser library exists
                library_path = build_dir / f"{lang}.so"
                grammar_dir = vendor_dir / f"tree-sitter-{grammar}"
                
                if not library_path.exists():
                    # If grammar directory doesn't exist, log warning and skip
                    if not grammar_dir.exists():
                        self.logger.warning(
                            f"Missing grammar for {lang}. Please run setup_parsers.py first."
                        )
                        continue
                        
                    self.logger.info(f"Building parser for {lang}...")
                    try:
                        Language.build_library(
                            str(library_path),
                            [str(grammar_dir)]
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Couldn't build {lang} parser: {str(e)}. "
                            "Pattern-based detection will still work."
                        )
                        continue
                
                # Load the language parser
                try:
                    language = Language(str(library_path), lang)
                    parser = Parser()
                    parser.set_language(language)
                    self.parsers[lang] = parser
                    self.logger.debug(f"Successfully loaded parser for {lang}")
                except Exception as e:
                    self.logger.warning(
                        f"Couldn't load {lang} parser: {str(e)}. "
                        "Pattern-based detection will still work."
                    )
            except Exception as e:
                self.logger.warning(
                    f"Error setting up parser for {lang}: {str(e)}. "
                    "Pattern-based detection will still work."
                )

    def parse(self, file_path: Path, content: str) -> Optional[Any]:
        """
        Parse code content to AST using the appropriate parser
        
        Attempts to parse the given content using the correct language parser.
        Falls back to Python's built-in AST parser for Python files if tree-sitter fails.
        
        Args:
            file_path: Path to the file being parsed
            content: Code content as a string
            
        Returns:
            AST object or None if parsing fails
            
        Raises:
            UnicodeDecodeError: If the content cannot be encoded properly
        """
        if not content or not content.strip():
            return None
            
        # Determine language from file extension
        ext = file_path.suffix.lstrip('.')
        if ext not in SUPPORTED_LANGUAGES:
            return None
            
        # Get parser for this language
        parser = self.parsers.get(ext)
        if not parser:
            # Fall back to Python's built-in AST for Python files
            if ext == 'py':
                try:
                    return self._parse_python_ast(content, file_path)
                except Exception as e:
                    self.logger.debug(f"Python AST parsing failed for {file_path.name}: {str(e)}")
                    return None
            return None
            
        # Parse with tree-sitter
        try:
            # Ensure content is properly encoded
            encoded_content = content.encode('utf-8', errors='replace')
            tree = parser.parse(encoded_content)
            return tree
        except Exception as e:
            self.logger.debug(f"Tree-sitter parsing failed for {file_path.name}: {str(e)}")
            return None
            
    def _parse_python_ast(self, content: str, file_path: Path) -> Optional[ast.AST]:
        """
        Parse Python code using built-in ast module
        
        Args:
            content: Python code as string
            file_path: Path to the file (for error reporting)
            
        Returns:
            Python AST or None if parsing fails
        """
        try:
            return ast.parse(content)
        except SyntaxError as e:
            self.logger.debug(f"Python syntax error in {file_path.name} at line {e.lineno}: {e.msg}")
            return None
        except Exception as e:
            self.logger.debug(f"Python AST parsing error in {file_path.name}: {str(e)}")
            return None
