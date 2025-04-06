"""
Environment verification for Vulnhound
"""
import importlib
import subprocess
import sys
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional, Set


class EnvironmentError(Exception):
    """Exception raised for errors in the environment setup"""
    pass


def check_environment(skip_ai: bool = False) -> bool:
    """
    Check if the environment has all required dependencies
    
    Verifies Python version, required packages, and external dependencies
    needed for Vulnhound to function properly.
    
    Args:
        skip_ai: If True, skip checking for AI model dependencies
        
    Returns:
        bool: True if environment is ready, False otherwise
        
    Raises:
        EnvironmentError: If a critical environment check fails
    """
    try:
        # Check Python version
        python_version = sys.version_info
        if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
            print("Error: Python 3.8 or higher is required")
            return False
        
        # Define core and AI dependencies
        core_packages = [
            "tree-sitter",
            "colorama",
            "jinja2",
        ]
        
        ai_packages = [
            "torch",
            "transformers",
            "numpy",
            "tqdm",
        ]
        
        # Check for required Python packages
        required_packages = core_packages
        if not skip_ai:
            required_packages.extend(ai_packages)
            
        missing_packages = _check_missing_packages(required_packages)
        
        if missing_packages:
            print(f"Missing required packages: {', '.join(missing_packages)}")
            print(f"Please install missing packages with: pip install {' '.join(missing_packages)}")
            return False
        
        # Check for required tree-sitter parsers
        if not _check_directory_exists('vendor'):
            print("Tree-sitter language repositories not found in vendor directory")
            print("Please run setup_parsers.py to set up language parsers")
            return False
            
        language_grammars = ['python', 'javascript', 'java', 'go', 'ruby']
        missing_grammars = _check_missing_grammars(language_grammars)
        
        if missing_grammars:
            print(f"Missing tree-sitter grammars: {', '.join(missing_grammars)}")
            print("Please run setup_parsers.py to download them")
            return False
        
        # Verify build directory exists
        build_dir = Path('build')
        if not build_dir.exists():
            build_dir.mkdir(exist_ok=True)
            print("Created build directory for tree-sitter parsers")
            
        # Check for HuggingFace model access if AI is enabled
        if not skip_ai and not _check_model_availability():
            print("Warning: Some AI models might not be available offline")
            print("Internet connection required for first-time model download")
            # This is just a warning, not an error
        
        return True
        
    except Exception as e:
        error_msg = f"Error during environment check: {str(e)}"
        print(error_msg)
        raise EnvironmentError(error_msg) from e


def _check_missing_packages(packages: List[str]) -> List[str]:
    """
    Check which Python packages from the provided list are missing
    
    Args:
        packages: List of package names to check
        
    Returns:
        List of missing package names
    """
    missing = []
    for package in packages:
        if not _is_package_installed(package):
            missing.append(package)
    return missing


def _is_package_installed(package_name: str) -> bool:
    """
    Check if a Python package is installed
    
    Args:
        package_name: Name of the package to check
        
    Returns:
        bool: True if installed, False otherwise
    """
    try:
        importlib.import_module(package_name.replace('-', '_'))
        return True
    except ImportError:
        return False


def _check_directory_exists(directory: str) -> bool:
    """
    Check if a directory exists
    
    Args:
        directory: Path to the directory
        
    Returns:
        bool: True if directory exists, False otherwise
    """
    return Path(directory).exists()


def _check_missing_grammars(languages: List[str]) -> List[str]:
    """
    Check which tree-sitter grammars are missing
    
    Args:
        languages: List of language grammar names to check
        
    Returns:
        List of missing grammar names
    """
    missing = []
    vendor_dir = Path('vendor')
    
    if not vendor_dir.exists():
        return languages
        
    for lang in languages:
        grammar_dir = vendor_dir / f'tree-sitter-{lang}'
        if not grammar_dir.exists():
            missing.append(lang)
            
    return missing


def _check_model_availability() -> bool:
    """
    Check if AI models are available or can be downloaded
    
    Returns:
        bool: True if models are available or can be downloaded, False otherwise
    """
    try:
        # Skip actual imports if torch is not installed to avoid hard dependency
        if not _is_package_installed('torch'):
            return False
            
        # Now import the specific components we need
        from transformers import AutoTokenizer
        
        # Check if we can access the internet to download models if needed
        try:
            import urllib.request
            urllib.request.urlopen('https://huggingface.co', timeout=3)
            return True
        except:
            # Check if models already exist locally
            try:
                from transformers.utils import TRANSFORMERS_CACHE
                cache_dir = Path(TRANSFORMERS_CACHE)
                
                # Just check if the cache directory exists and has content
                if cache_dir.exists() and any(cache_dir.iterdir()):
                    return True
            except:
                pass
            return False
    except ImportError:
        return False


def display_environment_info() -> Dict:
    """
    Display information about the current environment
    
    Returns:
        Dict containing environment information
    """
    info = {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "os": platform.system(),
        "packages": {},
        "cuda_available": False,
    }
    
    # Check for key packages
    packages = ["torch", "transformers", "tree-sitter", "numpy"]
    for package in packages:
        if _is_package_installed(package):
            try:
                module = importlib.import_module(package.replace('-', '_'))
                info["packages"][package] = getattr(module, "__version__", "unknown")
            except:
                info["packages"][package] = "installed"
        else:
            info["packages"][package] = "not installed"
    
    # Check for CUDA
    if _is_package_installed("torch"):
        import torch
        info["cuda_available"] = torch.cuda.is_available()
        if info["cuda_available"]:
            info["cuda_version"] = torch.version.cuda
    
    return info
