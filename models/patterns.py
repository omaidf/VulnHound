"""
Vulnerability patterns for pattern-based detection
"""
import re
from typing import List, Dict, Any, Optional, Pattern
from pathlib import Path

from models.vulnerability import Vulnerability, VulnerabilityType, SeverityLevel, CodeLocation


class VulnerabilityPattern:
    """Base class for vulnerability patterns"""
    
    def __init__(self, 
                 name: str,
                 vulnerability_type: VulnerabilityType,
                 severity: SeverityLevel,
                 description: str,
                 recommendation: str,
                 confidence: float = 0.7,
                 cwe_id: Optional[str] = None):
        self.name = name
        self.vulnerability_type = vulnerability_type
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.confidence = confidence
        self.cwe_id = cwe_id
    
    def find_in_code(self, content: str, ast) -> List[Vulnerability]:
        """
        Find vulnerability patterns in code
        
        Args:
            content: The code content as string
            ast: The AST of the code (optional)
            
        Returns:
            List of found vulnerabilities
        """
        raise NotImplementedError("Subclasses must implement this method")


class RegexPattern(VulnerabilityPattern):
    """Pattern that uses regex for detection"""
    
    def __init__(self, 
                 name: str,
                 vulnerability_type: VulnerabilityType,
                 regex_pattern: str,
                 severity: SeverityLevel,
                 description: str,
                 recommendation: str,
                 confidence: float = 0.7,
                 cwe_id: Optional[str] = None):
        super().__init__(name, vulnerability_type, severity, description, recommendation, confidence, cwe_id)
        self.regex = re.compile(regex_pattern, re.MULTILINE)
    
    def find_in_code(self, content: str, ast) -> List[Vulnerability]:
        """Find vulnerabilities using regex pattern matching"""
        vulnerabilities = []
        
        for match in self.regex.finditer(content):
            # Calculate line number from match position
            line_number = content[:match.start()].count('\n') + 1
            
            # Extract code snippet (the matched line)
            line_start = content.rfind('\n', 0, match.start()) + 1
            line_end = content.find('\n', match.start())
            if line_end == -1:  # If it's the last line
                line_end = len(content)
            code_snippet = content[line_start:line_end].strip()
            
            # Create vulnerability object
            location = CodeLocation(
                file_path=Path("unknown"),  # Will be set by the caller
                line_number=line_number,
                column=match.start() - line_start,
                code_snippet=code_snippet
            )
            
            vulnerability = Vulnerability(
                vulnerability_type=self.vulnerability_type,
                location=location,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                detector_type="pattern",
                detection_rule=self.regex.pattern,
                recommendation=self.recommendation,
                cwe_id=self.cwe_id
            )
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities


class ASTPattern(VulnerabilityPattern):
    """Pattern that uses AST for detection"""
    
    def find_in_code(self, content: str, ast) -> List[Vulnerability]:
        """Find vulnerabilities using AST pattern matching"""
        # AST-based detection would be implemented here
        # This is a placeholder for more complex AST-based detection
        return []


# Define common vulnerability patterns
# These are organized by language and common patterns
VULNERABILITY_PATTERNS = {
    # Python patterns
    "py": [
        RegexPattern(
            name="Python SQL Injection",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            regex_pattern=r'(?i)execute\(["\']SELECT.*\%s.*["\'].*\)',
            severity=SeverityLevel.HIGH,
            description="Potential SQL injection vulnerability in database query",
            recommendation="Use parameterized queries or ORM frameworks to prevent SQL injection",
            confidence=0.8,
            cwe_id="CWE-89"
        ),
        RegexPattern(
            name="Python Command Injection",
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            regex_pattern=r'(?:os\.system|subprocess\.call|subprocess\.Popen|subprocess\.run)\([^,)]*\b(?:format|join|replace|f["\'])',
            severity=SeverityLevel.CRITICAL,
            description="Potential command injection vulnerability",
            recommendation="Avoid using user input in shell commands, use parameter lists instead of string commands",
            confidence=0.9,
            cwe_id="CWE-78"
        ),
        RegexPattern(
            name="Python Hardcoded Credentials",
            vulnerability_type=VulnerabilityType.HARDCODED_CREDENTIALS,
            regex_pattern=r'(?i)(?:password|passwd|pwd|secret|key|token|apikey|api_key)\s*=\s*["\'][^"\']+["\']',
            severity=SeverityLevel.HIGH,
            description="Hardcoded credentials detected",
            recommendation="Store credentials in environment variables or a secure vault",
            confidence=0.7,
            cwe_id="CWE-798"
        ),
    ],
    
    # JavaScript patterns
    "js": [
        RegexPattern(
            name="JavaScript XSS",
            vulnerability_type=VulnerabilityType.XSS,
            regex_pattern=r'(?i)(?:innerHTML|outerHTML|document\.write|eval)\s*=',
            severity=SeverityLevel.HIGH,
            description="Potential Cross-Site Scripting vulnerability",
            recommendation="Use textContent instead of innerHTML, or sanitize user input before using it in HTML",
            confidence=0.8,
            cwe_id="CWE-79"
        ),
        RegexPattern(
            name="JavaScript Eval",
            vulnerability_type=VulnerabilityType.INSECURE_DESERIALIZATION,
            regex_pattern=r'(?i)eval\(.*\)',
            severity=SeverityLevel.HIGH,
            description="Use of eval() can lead to code execution vulnerabilities",
            recommendation="Avoid using eval(), use safer alternatives like JSON.parse()",
            confidence=0.9,
            cwe_id="CWE-95"
        ),
    ],
    
    # Java patterns
    "java": [
        RegexPattern(
            name="Java SQL Injection",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            regex_pattern=r'(?i)(?:prepareStatement|createQuery)\(["\']SELECT.*\+',
            severity=SeverityLevel.HIGH,
            description="Potential SQL injection vulnerability in database query",
            recommendation="Use parameterized queries and prepared statements properly",
            confidence=0.8,
            cwe_id="CWE-89"
        ),
    ],
    
    # Common patterns across languages
    "common": [
        RegexPattern(
            name="Insecure SSL/TLS",
            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
            regex_pattern=r'(?i)(?:verify\s*=\s*False|CERT_NONE|checkServerTrusted|InsecureRequestWarning|validate_cert\s*=\s*False)',
            severity=SeverityLevel.MEDIUM,
            description="Insecure SSL/TLS configuration detected",
            recommendation="Always validate SSL certificates in production",
            confidence=0.8,
            cwe_id="CWE-295"
        ),
        RegexPattern(
            name="Debug Flag",
            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
            regex_pattern=r'(?i)(?:DEBUG\s*=\s*True|development_mode\s*=\s*True)',
            severity=SeverityLevel.LOW,
            description="Debug mode might be enabled in production",
            recommendation="Ensure debug flags are disabled in production",
            confidence=0.6,
            cwe_id="CWE-489"
        ),
    ],
    
    # Add more patterns for other languages
    "go": [
        # Go-specific patterns
    ],
    "php": [
        # PHP-specific patterns
    ],
    "rb": [
        # Ruby-specific patterns
    ],
    "c": [
        # C-specific patterns
    ],
    "cpp": [
        # C++-specific patterns
    ],
    "cs": [
        # C#-specific patterns
    ],
}
