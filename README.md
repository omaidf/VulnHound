# Vulnhound

A powerful security vulnerability scanner for code repositories that leverages advanced AI models (CodeLlama and CodeBERT) along with pattern-based detection to identify security vulnerabilities in your code.

## Features

- **Advanced AI-Based Detection**: Uses CodeLlama and CodeBERT to identify complex vulnerabilities
- **Multi-Language Support**: Scans code in Python, JavaScript, Java, Go, PHP, Ruby, C, C++, and C#
- **No Configuration Needed**: Works out of the box without requiring templates or YAML files
- **Multiple Output Formats**: Generate reports in JSON, HTML, or console output
- **Tree-sitter Integration**: Leverages tree-sitter for accurate code parsing across languages
- **Environment Verification**: Automatically checks for required dependencies
- **Comprehensive Vulnerability Detection**: Identifies common security issues across multiple languages

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install from source

1. Clone this repository:
```bash
git clone https://github.com/your-username/vulnhound.git
cd vulnhound
```

2. Install the package:
```bash
pip install -e .
```

This will automatically install all required dependencies.

## Usage

### Basic Usage

Scan a repository with default settings:

```bash
vulnhound /path/to/your/repo
```

### Specifying File Extensions

Scan only specific file extensions:

```bash
vulnhound /path/to/your/repo --extensions py,js,java
```

### Output Formats

Generate a JSON report:

```bash
vulnhound /path/to/your/repo --output-format json --output-file vulnerabilities.json
```

Generate an HTML report:

```bash
vulnhound /path/to/your/repo --output-format html --output-file vulnerabilities.html
```

### Additional Options

Enable verbose logging:

```bash
vulnhound /path/to/your/repo -v
```

Skip environment verification:

```bash
vulnhound /path/to/your/repo --skip-environment-check
```

## Vulnerability Detection

Vulnhound detects vulnerabilities through two main techniques:

1. **Pattern-Based Detection**: Uses predefined patterns (regex and AST-based) to identify common security issues
2. **AI-Based Detection**: Leverages CodeLlama and CodeBERT models to identify complex vulnerabilities

### Detected Vulnerability Types

- SQL Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- Insecure Deserialization (CWE-502)
- Insecure Direct Object Reference (CWE-639)
- Broken Authentication (CWE-287)
- Sensitive Data Exposure (CWE-200)
- XML External Entity (CWE-611)
- Security Misconfiguration (CWE-1005)
- Cross-Site Request Forgery (CWE-352)
- Using Components with Known Vulnerabilities (CWE-1104)
- Unvalidated Redirects and Forwards (CWE-601)
- Server-Side Request Forgery (CWE-918)
- Business Logic Vulnerabilities (CWE-840)
- API Security Issues (CWE-1059)
- Hardcoded Credentials (CWE-798)
- Insufficient Logging & Monitoring (CWE-778)

## Architecture

The tool consists of the following components:

- **CLI Interface**: Handles command-line parsing and orchestrates the scanning process
- **Scanner**: Manages the scanning process and coordinates between components
- **Code Parser**: Parses code into AST using tree-sitter for more accurate analysis
- **AI Detector**: Uses CodeLlama and CodeBERT for advanced vulnerability detection
- **Pattern Matcher**: Uses predefined patterns to detect common vulnerabilities
- **Report Generator**: Creates formatted reports in various output formats

## Development

### Running Tests

```bash
python -m unittest discover tests
```

### Adding New Patterns

To add new vulnerability patterns, edit the `models/patterns.py` file and add your patterns to the appropriate language section in the `VULNERABILITY_PATTERNS` dictionary.

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
