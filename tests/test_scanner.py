"""
Test module for the Scanner functionality
"""
import os
import unittest
from pathlib import Path
import tempfile

from core.scanner import Scanner
from utils.logger import setup_logger


class TestScanner(unittest.TestCase):
    """Test cases for the Scanner functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.logger = setup_logger(verbose=False)
        
        # Create a temporary directory with test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_path = Path(self.temp_dir.name)
        
        # Create a vulnerable Python file
        python_file = self.repo_path / "vulnerable.py"
        with open(python_file, "w") as f:
            f.write("""
import os

def execute_query(user_input):
    query = "SELECT * FROM users WHERE id = %s" % user_input
    return query

def run_command(command):
    os.system(command)  # Command injection vulnerability

PASSWORD = "hardcoded_password_123"  # Hardcoded credentials
            """)
        
        # Create a vulnerable JavaScript file
        js_file = self.repo_path / "vulnerable.js"
        with open(js_file, "w") as f:
            f.write("""
function displayUserData(userData) {
    document.getElementById('output').innerHTML = userData;  // XSS vulnerability
}

function executeCode(code) {
    eval(code);  // Eval vulnerability
}

const API_KEY = "secret_api_key_12345";  // Hardcoded credentials
            """)
    
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
    
    def test_scanner_detects_vulnerabilities(self):
        """Test that the scanner correctly detects vulnerabilities"""
        scanner = Scanner(self.repo_path, ["py", "js"], self.logger)
        vulnerabilities = scanner.scan()
        
        # Verify that vulnerabilities were found
        self.assertGreater(len(vulnerabilities), 0, "No vulnerabilities were detected")
        
        # Check if SQL injection was detected in Python file
        sql_injection_found = any(
            v.vulnerability_type.value == "SQL Injection" for v in vulnerabilities
        )
        self.assertTrue(sql_injection_found, "SQL Injection not detected")
        
        # Check if XSS was detected in JavaScript file
        xss_found = any(
            v.vulnerability_type.value == "Cross-Site Scripting" for v in vulnerabilities
        )
        self.assertTrue(xss_found, "XSS not detected")
        
        # Check if hardcoded credentials were detected
        hardcoded_creds_found = any(
            v.vulnerability_type.value == "Hardcoded Credentials" for v in vulnerabilities
        )
        self.assertTrue(hardcoded_creds_found, "Hardcoded credentials not detected")


if __name__ == "__main__":
    unittest.main()
