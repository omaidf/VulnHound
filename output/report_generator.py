"""
Report generator for Vulnhound vulnerability findings
"""
import os
import json
import datetime
from typing import List, Dict, Any
from pathlib import Path
import jinja2

from models.vulnerability import Vulnerability, SeverityLevel


def generate_report(vulnerabilities: List[Vulnerability], output_format: str, output_file: str, logger):
    """
    Generate a report of detected vulnerabilities
    
    Args:
        vulnerabilities: List of detected vulnerabilities
        output_format: Format of the report ('json', 'html', or 'console')
        output_file: Path to save the report (not needed for console output)
        logger: Logger instance
    """
    if output_format == "console":
        _generate_console_report(vulnerabilities, logger)
    elif output_format == "json":
        _generate_json_report(vulnerabilities, output_file, logger)
    elif output_format == "html":
        _generate_html_report(vulnerabilities, output_file, logger)
    else:
        logger.error(f"Unsupported output format: {output_format}")


def _generate_console_report(vulnerabilities: List[Vulnerability], logger):
    """
    Generate a console report of vulnerabilities
    
    Args:
        vulnerabilities: List of detected vulnerabilities
        logger: Logger instance
    """
    if not vulnerabilities:
        logger.info("No vulnerabilities detected")
        return
    
    logger.info(f"Found {len(vulnerabilities)} potential security vulnerabilities")
    
    # Group vulnerabilities by severity
    by_severity = {}
    for vuln in vulnerabilities:
        if vuln.severity not in by_severity:
            by_severity[vuln.severity] = []
        by_severity[vuln.severity].append(vuln)
    
    # Display vulnerabilities by severity (most severe first)
    severity_order = [
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        SeverityLevel.LOW,
        SeverityLevel.INFO
    ]
    
    for severity in severity_order:
        if severity in by_severity:
            vulns = by_severity[severity]
            logger.info(f"\n{severity.value} Severity ({len(vulns)} found):")
            
            for i, vuln in enumerate(vulns, 1):
                logger.info(f"  {i}. {vuln.vulnerability_type.value}")
                logger.info(f"     File: {vuln.location.file_path}")
                logger.info(f"     Line: {vuln.location.line_number}")
                if vuln.location.code_snippet:
                    logger.info(f"     Code: {vuln.location.code_snippet}")
                logger.info(f"     Description: {vuln.description}")
                if vuln.recommendation:
                    logger.info(f"     Recommendation: {vuln.recommendation}")
                if vuln.cwe_id:
                    logger.info(f"     CWE ID: {vuln.cwe_id}")
                logger.info(f"     Confidence: {vuln.confidence:.0%}")
                logger.info("")


def _generate_json_report(vulnerabilities: List[Vulnerability], output_file: str, logger):
    """
    Generate a JSON report of vulnerabilities
    
    Args:
        vulnerabilities: List of detected vulnerabilities
        output_file: Path to save the report
        logger: Logger instance
    """
    # Convert vulnerabilities to dictionaries
    vuln_dicts = [vuln.to_dict() for vuln in vulnerabilities]
    
    # Create report data
    report = {
        "generated_at": datetime.datetime.now().isoformat(),
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vuln_dicts,
        "summary": _generate_summary(vulnerabilities)
    }
    
    # Write to file
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        logger.info(f"JSON report saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving JSON report: {str(e)}")


def _generate_html_report(vulnerabilities: List[Vulnerability], output_file: str, logger):
    """
    Generate an HTML report of vulnerabilities
    
    Args:
        vulnerabilities: List of detected vulnerabilities
        output_file: Path to save the report
        logger: Logger instance
    """
    # Convert vulnerabilities to dictionaries
    vuln_dicts = [vuln.to_dict() for vuln in vulnerabilities]
    
    # Create summary
    summary = _generate_summary(vulnerabilities)
    
    # Load HTML template
    try:
        # Create Jinja2 environment with template from string
        env = jinja2.Environment(autoescape=True)
        template = env.from_string(HTML_TEMPLATE)
        
        # Render the template
        html_content = template.render(
            generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_vulnerabilities=len(vulnerabilities),
            vulnerabilities=vuln_dicts,
            summary=summary
        )
        
        # Write to file
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"HTML report saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving HTML report: {str(e)}")


def _generate_summary(vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
    """
    Generate a summary of vulnerability statistics
    
    Args:
        vulnerabilities: List of detected vulnerabilities
        
    Returns:
        Dictionary with summary information
    """
    # Count by severity
    by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    # Count by type
    by_type = {}
    
    # Count by file
    by_file = {}
    
    for vuln in vulnerabilities:
        # Count by severity
        severity = vuln.severity.value.lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        # Count by type
        vuln_type = vuln.vulnerability_type.value
        by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
        
        # Count by file
        file_path = str(vuln.location.file_path)
        by_file[file_path] = by_file.get(file_path, 0) + 1
    
    return {
        "by_severity": by_severity,
        "by_type": by_type,
        "by_file": by_file,
        "total": len(vulnerabilities)
    }


# HTML report template using Bootstrap for styling
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnhound Security Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding: 20px; }
        .vulnerability-card { margin-bottom: 15px; }
        .critical { border-left: 5px solid #dc3545; }
        .high { border-left: 5px solid #fd7e14; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #0dcaf0; }
        .info { border-left: 5px solid #6c757d; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }
        .chart-container { height: 200px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="row mb-4">
            <div class="col">
                <h1>Vulnhound Security Report</h1>
                <p class="text-muted">Generated on {{ generated_at }}</p>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="card-title mb-0">Summary</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4">
                                <h5>Vulnerabilities by Severity</h5>
                                <ul class="list-group">
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        Critical
                                        <span class="badge bg-danger rounded-pill">{{ summary.by_severity.critical }}</span>
                                    </li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        High
                                        <span class="badge bg-warning text-dark rounded-pill">{{ summary.by_severity.high }}</span>
                                    </li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        Medium
                                        <span class="badge bg-info text-dark rounded-pill">{{ summary.by_severity.medium }}</span>
                                    </li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        Low
                                        <span class="badge bg-secondary rounded-pill">{{ summary.by_severity.low }}</span>
                                    </li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        Informational
                                        <span class="badge bg-light text-dark rounded-pill">{{ summary.by_severity.info }}</span>
                                    </li>
                                </ul>
                            </div>
                            <div class="col-md-8">
                                <h5>Top Vulnerability Types</h5>
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Type</th>
                                            <th>Count</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for type, count in summary.by_type.items() %}
                                        <tr>
                                            <td>{{ type }}</td>
                                            <td>{{ count }}</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col">
                <h2>Detected Vulnerabilities ({{ total_vulnerabilities }})</h2>
                
                {% if total_vulnerabilities == 0 %}
                <div class="alert alert-success">
                    No vulnerabilities detected! Great job!
                </div>
                {% else %}
                
                {% for vuln in vulnerabilities %}
                <div class="card vulnerability-card {{ vuln.severity.lower() }}">
                    <div class="card-header">
                        <h5 class="card-title mb-0">{{ vuln.type }}</h5>
                    </div>
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">
                            Severity: <span class="badge bg-{{ 'danger' if vuln.severity.lower() == 'critical' else 'warning' if vuln.severity.lower() == 'high' else 'info' if vuln.severity.lower() == 'medium' else 'secondary' if vuln.severity.lower() == 'low' else 'light text-dark' }}">
                                {{ vuln.severity }}
                            </span>
                            {% if vuln.cwe_id %}
                            | CWE: <span class="badge bg-secondary">{{ vuln.cwe_id }}</span>
                            {% endif %}
                            | Confidence: <span class="badge bg-secondary">{{ (vuln.confidence * 100)|int }}%</span>
                        </h6>
                        
                        <p><strong>Description:</strong> {{ vuln.description }}</p>
                        
                        <p><strong>Location:</strong> {{ vuln.file_path }}:{{ vuln.line_number }}</p>
                        
                        {% if vuln.code_snippet %}
                        <div class="mb-3">
                            <strong>Code:</strong>
                            <pre>{{ vuln.code_snippet }}</pre>
                        </div>
                        {% endif %}
                        
                        {% if vuln.recommendation %}
                        <div class="mb-3">
                            <strong>Recommendation:</strong>
                            <p>{{ vuln.recommendation }}</p>
                        </div>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
                
                {% endif %}
            </div>
        </div>
    </div>

    <footer class="bg-light py-3 mt-5">
        <div class="container text-center">
            <p class="text-muted mb-0">Generated by Vulnhound - Security Vulnerability Scanner</p>
        </div>
    </footer>
</body>
</html>
"""
