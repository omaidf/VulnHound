#!/usr/bin/env python3
"""
Setup script to download tree-sitter grammars for Vulnhound

This script automatically downloads the required tree-sitter parsers
for all supported languages and prepares the environment for code parsing.
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple


# Define the supported language grammars
GRAMMARS = {
    'python': 'https://github.com/tree-sitter/tree-sitter-python',
    'javascript': 'https://github.com/tree-sitter/tree-sitter-javascript',
    'java': 'https://github.com/tree-sitter/tree-sitter-java',
    'go': 'https://github.com/tree-sitter/tree-sitter-go',
    'ruby': 'https://github.com/tree-sitter/tree-sitter-ruby',
    'php': 'https://github.com/tree-sitter/tree-sitter-php',
    'c': 'https://github.com/tree-sitter/tree-sitter-c',
    'cpp': 'https://github.com/tree-sitter/tree-sitter-cpp',
    'c_sharp': 'https://github.com/tree-sitter/tree-sitter-c-sharp',
    'typescript': 'https://github.com/tree-sitter/tree-sitter-typescript',
}


def check_git_installed() -> bool:
    """
    Check if git is installed on the system
    
    Returns:
        bool: True if git is installed, False otherwise
    """
    try:
        subprocess.run(['git', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def setup_directories() -> Tuple[Path, Path]:
    """
    Create the necessary directories for tree-sitter parsers
    
    Returns:
        Tuple of (vendor_dir, build_dir)
    """
    # Get the project root directory
    root_dir = Path(__file__).parent
    
    # Create vendor directory
    vendor_dir = root_dir / 'vendor'
    vendor_dir.mkdir(exist_ok=True)
    
    # Create build directory
    build_dir = root_dir / 'build'
    build_dir.mkdir(exist_ok=True)
    
    return vendor_dir, build_dir


def clone_grammars(vendor_dir: Path) -> List[str]:
    """
    Clone tree-sitter grammar repositories
    
    Args:
        vendor_dir: Path to vendor directory
        
    Returns:
        List of successfully cloned grammar names
    """
    success_list = []
    
    for name, url in GRAMMARS.items():
        repo_dir = vendor_dir / f'tree-sitter-{name}'
        
        if repo_dir.exists():
            print(f"[✓] Grammar '{name}' already exists, updating...")
            try:
                subprocess.run(
                    ['git', 'pull', 'origin', 'master'], 
                    cwd=repo_dir,
                    capture_output=True,
                    check=True
                )
                success_list.append(name)
                print(f"[✓] Successfully updated grammar for {name}")
            except subprocess.SubprocessError as e:
                print(f"[✗] Error updating grammar for {name}: {e}")
                # Keep it in success list if it already exists
                success_list.append(name)
        else:
            print(f"[*] Downloading grammar for {name}...")
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '1', url, str(repo_dir)], 
                    check=True,
                    capture_output=True
                )
                success_list.append(name)
                print(f"[✓] Successfully downloaded grammar for {name}")
            except subprocess.SubprocessError as e:
                print(f"[✗] Error downloading grammar for {name}: {e}")
    
    return success_list


def main():
    """Set up tree-sitter parsers for Vulnhound"""
    print("╔══════════════════════════════════════════════════════╗")
    print("║     Setting up tree-sitter parsers for Vulnhound      ║")
    print("╚══════════════════════════════════════════════════════╝")
    
    # Check if git is installed
    if not check_git_installed():
        print("[✗] Error: git is not installed or not in PATH")
        print("    Please install git and try again.")
        return 1
    
    try:
        # Setup directories
        vendor_dir, build_dir = setup_directories()
        
        # Clone repositories
        print("\n[*] Downloading language grammars...")
        success_list = clone_grammars(vendor_dir)
        
        if not success_list:
            print("\n[✗] Failed to download any grammars. Check your internet connection and try again.")
            return 1
            
        # Success message
        print("\n[✓] Tree-sitter grammars setup complete!")
        print(f"[✓] Successfully set up {len(success_list)} language parsers: {', '.join(success_list)}")
        print("[*] Next steps:")
        print("    1. Run 'pip install -r requirements.txt' to install Python dependencies")
        print("    2. Run './vulnhound.py --help' to see available options")
        print("    3. Start scanning with './vulnhound.py /path/to/your/repo'")
        
        return 0
        
    except Exception as e:
        print(f"[✗] Error during setup: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
