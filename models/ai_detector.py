"""
AI-based vulnerability detector using CodeLLaMA and CodeBERT
"""
import os
import time
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import logging

import torch
import numpy as np
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification,
    AutoModelForCausalLM,
    pipeline
)

from models.vulnerability import Vulnerability, VulnerabilityType, SeverityLevel, CodeLocation

# Mapping of vulnerability types to potential CWE IDs
VULNERABILITY_TO_CWE = {
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "insecure_deserialization": "CWE-502",
    "hardcoded_credentials": "CWE-798",
    "broken_authentication": "CWE-287",
    "sensitive_data_exposure": "CWE-200",
    "xxe": "CWE-611",
    "security_misconfiguration": "CWE-1005",
    "csrf": "CWE-352",
    "using_components_with_vulnerabilities": "CWE-1104",
    "unvalidated_redirects": "CWE-601",
    "ssrf": "CWE-918",
    "business_logic": "CWE-840",
    "api_security": "CWE-1059",
    "insufficient_logging": "CWE-778",
}

# Maps severity string values to enum
SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
}

# Maps vulnerability type strings to enum values
VULNERABILITY_TYPE_MAP = {
    "sql_injection": VulnerabilityType.SQL_INJECTION,
    "xss": VulnerabilityType.XSS,
    "command_injection": VulnerabilityType.COMMAND_INJECTION,
    "path_traversal": VulnerabilityType.PATH_TRAVERSAL,
    "insecure_deserialization": VulnerabilityType.INSECURE_DESERIALIZATION,
    "idor": VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
    "broken_authentication": VulnerabilityType.BROKEN_AUTHENTICATION,
    "sensitive_data_exposure": VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
    "xxe": VulnerabilityType.XML_EXTERNAL_ENTITY,
    "security_misconfiguration": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "csrf": VulnerabilityType.CSRF,
    "using_components_with_vulnerabilities": VulnerabilityType.USING_COMPONENTS_WITH_VULNERABILITIES,
    "unvalidated_redirects": VulnerabilityType.UNVALIDATED_REDIRECTS,
    "ssrf": VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY,
    "business_logic": VulnerabilityType.BUSINESS_LOGIC_VULNERABILITY,
    "api_security": VulnerabilityType.API_SECURITY,
    "hardcoded_credentials": VulnerabilityType.HARDCODED_CREDENTIALS,
    "insufficient_logging": VulnerabilityType.INSUFFICIENT_LOGGING,
}


class AIModelLoadError(Exception):
    """Exception raised for errors when loading AI models"""
    pass


class AIDetector:
    """
    Uses AI models (CodeLLaMA and CodeBERT) to detect vulnerabilities in code.
    
    This class provides advanced vulnerability detection capabilities using
    pretrained AI models. It combines a classification approach (CodeBERT)
    to detect potentially vulnerable code, with a generative model (CodeLLaMA)
    that provides detailed vulnerability descriptions and recommendations.
    
    The detector gracefully degrades if models are not available and can operate
    in offline mode if needed.
    """
    
    def __init__(self, logger):
        """
        Initialize the AI detector with necessary models
        
        Args:
            logger: Logger instance for tracking model operations
        """
        self.logger = logger
        self.models = {}
        self.tokenizers = {}
        self.initialized = False
        
        # Determine the best device to use (CUDA GPU if available, otherwise CPU)
        self.device = self._get_optimal_device()
        
        # Defer initialization to first use to avoid loading models unnecessarily
        
    def _get_optimal_device(self) -> str:
        """
        Determine the best device for model inference
        
        Returns:
            String representing the device to use ('cuda', 'mps', or 'cpu')
        """
        if torch.cuda.is_available():
            self.logger.debug("CUDA device detected, will use GPU acceleration if models are loaded")
            return "cuda"
        elif hasattr(torch, 'mps') and torch.backends.mps.is_available():
            self.logger.debug("Apple M-series GPU detected, will use MPS acceleration if models are loaded")
            return "mps"
        else:
            self.logger.debug("No GPU detected, will use CPU for model inference")
            return "cpu"
        
    def _initialize_models(self):
        """
        Initialize the AI models for vulnerability detection
        
        This method:
        1. Checks for existing model cache
        2. Attempts to download models if needed and possible
        3. Loads models with appropriate optimizations based on hardware
        
        Raises:
            AIModelLoadError: If critical errors occur during model initialization
        """
        if self.initialized:
            return
        
        start_time = time.time()
        self.logger.info("Initializing AI models for vulnerability detection...")
        
        try:
            # Set up internal transformers logging to avoid verbose output
            transformers_logger = logging.getLogger("transformers")
            transformers_logger.setLevel(logging.ERROR)
            
            # Initialize CodeBERT for vulnerability classification (smaller model, try first)
            try:
                model_name = "microsoft/codebert-base-mlm"
                self.logger.info(f"Loading CodeBERT model ({model_name})...")
                
                self.tokenizers["codebert"] = AutoTokenizer.from_pretrained(
                    model_name, 
                    local_files_only=not self._can_download_models()
                )
                
                self.models["codebert"] = AutoModelForSequenceClassification.from_pretrained(
                    model_name, 
                    num_labels=2,
                    local_files_only=not self._can_download_models()
                )
                
                self.models["codebert"].to(self.device)
                self.logger.info(f"Successfully loaded CodeBERT model")
                
            except Exception as e:
                self.logger.warning(f"Error loading CodeBERT: {str(e)}")
                self.logger.info("Pattern-based detection will still work")
            
            # Initialize CodeLLaMA for vulnerability description and recommendation (larger model)
            try:
                llama_model_name = "codellama/CodeLlama-7b-Instruct-hf"
                should_download = self._can_download_models()
                
                if os.path.exists(llama_model_name) or should_download:
                    self.logger.info(f"Loading CodeLlama model ({llama_model_name})...")
                    self.logger.info("This may take a few minutes for the first run...")
                    
                    self.tokenizers["codellama"] = AutoTokenizer.from_pretrained(
                        llama_model_name,
                        local_files_only=not should_download
                    )
                    
                    # Apply hardware-specific optimizations
                    load_in_8bit = self.device == "cuda"  # Only use 8-bit quantization on CUDA
                    
                    self.models["codellama"] = AutoModelForCausalLM.from_pretrained(
                        llama_model_name, 
                        load_in_8bit=load_in_8bit,
                        device_map="auto" if self.device == "cuda" else None,
                        local_files_only=not should_download
                    )
                    
                    # Move to appropriate device if not using device_map="auto"
                    if self.device != "cuda":
                        self.models["codellama"].to(self.device)
                        
                    self.logger.info(f"Successfully loaded CodeLlama model")
                else:
                    self.logger.warning(
                        "CodeLlama model not available locally and cannot be downloaded. "
                        "LLM-based analysis will be disabled."
                    )
            except Exception as e:
                self.logger.warning(f"Error loading CodeLlama: {str(e)}")
                self.logger.info("CodeBERT will still be used for vulnerability detection if available")
                
            self.initialized = True
            elapsed_time = time.time() - start_time
            self.logger.info(f"AI models initialized in {elapsed_time:.2f} seconds")
            
        except Exception as e:
            error_msg = f"Critical error initializing AI models: {str(e)}"
            self.logger.error(error_msg)
            # Continue without AI models - we'll fall back to pattern-based detection
            self.logger.info("Falling back to pattern-based detection only")
    
    def _can_download_models(self) -> bool:
        """
        Check if we can download models from the internet
        
        Returns:
            Boolean indicating if internet connectivity is available
        """
        try:
            import urllib.request
            # Try to connect to Hugging Face
            urllib.request.urlopen('https://huggingface.co', timeout=3)
            return True
        except Exception:
            return False
    
    def detect_vulnerabilities(self, file_path: Path, content: str, ast) -> List[Vulnerability]:
        """
        Detect vulnerabilities using AI models
        
        This method orchestrates the AI-based vulnerability detection process:
        1. Initializes models if needed
        2. Splits content into manageable chunks
        3. Analyzes each chunk with CodeBERT
        4. For potential vulnerabilities, uses CodeLlama to provide details
        
        Args:
            file_path: Path to the file being analyzed
            content: Source code content as string
            ast: Abstract Syntax Tree (optional, may be None)
            
        Returns:
            List of vulnerabilities detected by AI models
            
        Raises:
            Exception: If a critical error occurs during analysis
        """
        # Skip empty files
        if not content or not content.strip():
            return []
        
        vulnerabilities = []
        
        try:
            # Lazy initialization of models
            if not self.initialized:
                self._initialize_models()
                
            # If no models were successfully loaded, return empty list
            if not self.models:
                return []
                
            # Split content into chunks to avoid exceeding model context limit
            chunks = self._split_content_into_chunks(content)
            
            # Process each chunk
            for chunk_idx, (chunk, start_line) in enumerate(chunks):
                # Skip empty chunks
                if not chunk.strip():
                    continue
                
                # Analyze chunk with CodeBERT for vulnerability detection
                if "codebert" in self.models:
                    vuln_detected, confidence = self._analyze_with_codebert(chunk)
                    
                    if vuln_detected and confidence > 0.7:
                        # If vulnerability detected, use CodeLLaMA to describe it (if available)
                        vuln_info = None
                        if "codellama" in self.models:
                            vuln_info = self._analyze_with_codellama(chunk)
                        
                        if not vuln_info:
                            # If CodeLlama failed or isn't available, use a generic description
                            vuln_info = {
                                "type": "other",
                                "description": "Potential security vulnerability detected by AI model",
                                "severity": "medium",
                                "line_offset": 0,
                                "recommendation": "Review the code for security issues"
                            }
                        
                        # Extract information from vuln_info
                        vuln_type = vuln_info.get("type", "other")
                        description = vuln_info.get("description", "Potential security vulnerability detected")
                        recommendation = vuln_info.get("recommendation", "Review this code for security issues")
                        severity_str = vuln_info.get("severity", "medium").lower()
                        line_offset = vuln_info.get("line_offset", 0)
                        
                        # Map to proper enums
                        severity = SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)
                        vuln_type_enum = VULNERABILITY_TYPE_MAP.get(vuln_type, VulnerabilityType.OTHER)
                        
                        # Calculate actual line number
                        line_number = start_line + line_offset
                        
                        # Get code snippet
                        lines = chunk.splitlines()
                        if 0 <= line_offset < len(lines):
                            code_snippet = lines[line_offset]
                        else:
                            code_snippet = lines[0] if lines else chunk[:100]
                        
                        # Create vulnerability object
                        location = CodeLocation(
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=code_snippet
                        )
                        
                        vulnerability = Vulnerability(
                            vulnerability_type=vuln_type_enum,
                            location=location,
                            description=description,
                            severity=severity,
                            confidence=confidence,
                            detector_type="ai",
                            recommendation=recommendation,
                            cwe_id=VULNERABILITY_TO_CWE.get(vuln_type, None)
                        )
                        
                        vulnerabilities.append(vulnerability)
        
        except Exception as e:
            self.logger.error(f"Error in AI-based detection: {str(e)}")
            # Return any vulnerabilities found before the error
        
        return vulnerabilities
    
    def _split_content_into_chunks(self, content: str, chunk_size: int = 1000) -> List[Tuple[str, int]]:
        """
        Split content into manageable chunks for AI processing
        
        This avoids exceeding model token limits and improves processing efficiency.
        
        Args:
            content: Code content
            chunk_size: Maximum number of characters per chunk
            
        Returns:
            List of (chunk, start_line) tuples where start_line is 0-indexed
        """
        lines = content.splitlines()
        chunks = []
        current_chunk = []
        current_size = 0
        start_line = 0
        
        for i, line in enumerate(lines):
            line_size = len(line)
            
            if current_size + line_size > chunk_size and current_chunk:
                # If adding this line exceeds chunk size, finalize current chunk
                chunks.append(('\n'.join(current_chunk), start_line))
                current_chunk = [line]
                current_size = line_size
                start_line = i
            else:
                # Add line to current chunk
                current_chunk.append(line)
                current_size += line_size
        
        # Add the last chunk if it has content
        if current_chunk:
            chunks.append(('\n'.join(current_chunk), start_line))
        
        return chunks
    
    def _analyze_with_codebert(self, code: str) -> Tuple[bool, float]:
        """
        Analyze code with CodeBERT to detect vulnerabilities
        
        Args:
            code: Code snippet to analyze
            
        Returns:
            Tuple of (is_vulnerable, confidence)
            
        Raises:
            Exception: If a critical error occurs during analysis
        """
        try:
            tokenizer = self.tokenizers["codebert"]
            model = self.models["codebert"]
            
            # Encode the input with proper truncation
            inputs = tokenizer(
                code, 
                return_tensors="pt", 
                truncation=True, 
                max_length=512
            ).to(self.device)
            
            # Run model inference
            with torch.no_grad():
                outputs = model(**inputs)
            
            # Get probabilities
            probs = torch.softmax(outputs.logits, dim=1)
            is_vulnerable = bool(torch.argmax(probs, dim=1).item())
            confidence = probs[0][int(is_vulnerable)].item()
            
            return is_vulnerable, confidence
            
        except Exception as e:
            self.logger.error(f"Error in CodeBERT analysis: {str(e)}")
            return False, 0.0
    
    def _analyze_with_codellama(self, code: str) -> Optional[Dict[str, Any]]:
        """
        Use CodeLLaMA to analyze potentially vulnerable code
        
        Performs generative analysis to provide detailed vulnerability information.
        
        Args:
            code: Code snippet to analyze
            
        Returns:
            Dictionary with vulnerability information or None if analysis fails
        """
        try:
            tokenizer = self.tokenizers["codellama"]
            model = self.models["codellama"]
            
            # Create a clear, structured prompt for the LLM
            prompt = f"""<Instruction>
Analyze the following code for security vulnerabilities. If you find any, describe:
1. The type of vulnerability (e.g., sql_injection, xss, command_injection, path_traversal)
2. A brief description of the issue
3. The severity (critical, high, medium, low, or info)
4. Which line contains the vulnerability (as a line offset from the start of the snippet)
5. A recommendation to fix it

Code to analyze:
```
{code}
```
</Instruction>"""
            
            # Tokenize and generate with proper parameters
            inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
            
            with torch.no_grad():
                outputs = model.generate(
                    inputs["input_ids"],
                    max_new_tokens=256,
                    do_sample=False,
                    temperature=0.1,
                    pad_token_id=tokenizer.eos_token_id
                )
            
            # Decode the response
            response = tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extract the model's response (after the instruction)
            response_text = response.split("</Instruction>")[-1].strip()
            
            # Parse the response to extract structured information
            vuln_info = self._parse_llama_response(response_text)
            return vuln_info
            
        except Exception as e:
            self.logger.error(f"Error in CodeLLaMA analysis: {str(e)}")
            return None
    
    def _parse_llama_response(self, response: str) -> Dict[str, Any]:
        """
        Parse LLaMA's response to extract structured vulnerability information
        
        Processes the free-text LLM output into a structured dictionary.
        
        Args:
            response: LLaMA's text response
            
        Returns:
            Dictionary with vulnerability information
        """
        # Default values
        result = {
            "type": "other",
            "description": "Potential security vulnerability",
            "severity": "medium",
            "line_offset": 0,
            "recommendation": "Review the code for security issues"
        }
        
        # Extract vulnerability type
        vulnerability_types = {
            "sql injection": "sql_injection",
            "xss": "xss",
            "cross-site scripting": "xss",
            "command injection": "command_injection",
            "path traversal": "path_traversal",
            "directory traversal": "path_traversal",
            "deserialization": "insecure_deserialization",
            "hardcoded credential": "hardcoded_credentials",
            "hardcoded password": "hardcoded_credentials",
            "hardcoded secret": "hardcoded_credentials",
            "authentication": "broken_authentication",
            "authorization": "broken_authentication",
            "sensitive data": "sensitive_data_exposure",
            "xxe": "xxe",
            "xml external": "xxe",
            "misconfiguration": "security_misconfiguration",
            "csrf": "csrf",
            "cross-site request forgery": "csrf",
            "redirect": "unvalidated_redirects",
            "ssrf": "ssrf",
            "server-side request forgery": "ssrf",
            "api key": "hardcoded_credentials",
        }
        
        # Identify vulnerability type from response
        for key, value in vulnerability_types.items():
            if key.lower() in response.lower():
                result["type"] = value
                break
        
        # Extract severity
        severity_patterns = ["critical", "high", "medium", "low", "info"]
        for pattern in severity_patterns:
            if pattern.lower() in response.lower():
                result["severity"] = pattern
                break
        
        # Extract description
        description_markers = ["description:", "issue:", "vulnerability:", "problem:"]
        for marker in description_markers:
            if marker in response.lower():
                lines = response.split("\n")
                for i, line in enumerate(lines):
                    if marker.lower() in line.lower() and i < len(lines)-1:
                        # Get the next line as the description
                        result["description"] = lines[i+1].strip()
                        break
        
        # If no specific description was found, try to extract one from the first part of the response
        if result["description"] == "Potential security vulnerability":
            # Get the first few lines as a fallback description
            lines = [line.strip() for line in response.split("\n") if line.strip()]
            if lines:
                result["description"] = lines[0].strip()
        
        # Extract line offset
        import re
        line_matches = re.findall(r"line (\d+)", response.lower())
        if line_matches:
            try:
                result["line_offset"] = max(0, int(line_matches[0]) - 1)  # Convert to 0-based
            except ValueError:
                pass
        
        # Extract recommendation
        recommendation_markers = ["recommendation:", "fix:", "solution:", "remediation:"]
        for marker in recommendation_markers:
            if marker.lower() in response.lower():
                lines = response.split("\n")
                for i, line in enumerate(lines):
                    if marker.lower() in line.lower() and i < len(lines)-1:
                        # Get the next line as the recommendation
                        result["recommendation"] = lines[i+1].strip()
                        # Check if there are more lines that seem to be part of the recommendation
                        for j in range(i+2, min(i+5, len(lines))):
                            if lines[j].strip() and not any(m in lines[j].lower() for m in 
                                                           description_markers + recommendation_markers + ["severity:", "line:", "type:"]):
                                result["recommendation"] += " " + lines[j].strip()
                            else:
                                break
                        break
        
        return result
