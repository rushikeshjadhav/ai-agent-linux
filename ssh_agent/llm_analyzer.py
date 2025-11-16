import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

logger = logging.getLogger(__name__)

class LLMProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OPENROUTER = "openrouter"

@dataclass
class AnalysisResult:
    """Result of LLM analysis"""
    summary: str
    issues: List[str]
    recommendations: List[str]
    severity: str  # low, medium, high, critical
    confidence: float

@dataclass
class ActionPlan:
    """LLM-generated action plan"""
    goal: str
    steps: List[Dict[str, Any]]
    risks: List[str]
    estimated_time: str
    safety_score: float

class ServerStateAnalyzer:
    """Uses LLM to analyze server state and suggest actions"""
    
    def __init__(self, provider: LLMProvider = LLMProvider.OPENAI, api_key: Optional[str] = None):
        self.provider = provider
        self.api_key = api_key
        self._client = None
        self._setup_client()
    
    def _setup_client(self):
        """Initialize LLM client"""
        if self.provider == LLMProvider.OPENAI and HAS_OPENAI:
            self._client = openai.OpenAI(api_key=self.api_key)
        elif self.provider == LLMProvider.OPENROUTER and HAS_OPENAI:
            self._client = openai.OpenAI(
                api_key=self.api_key,
                base_url="https://openrouter.ai/api/v1"
            )
        elif self.provider == LLMProvider.ANTHROPIC and HAS_ANTHROPIC:
            self._client = anthropic.Anthropic(api_key=self.api_key)
        else:
            logger.warning(f"LLM provider {self.provider.value} not available")
    
    def analyze_system_state(self, command_results: Dict[str, str]) -> AnalysisResult:
        """Analyze multiple command outputs to understand system state"""
        if not self._client:
            return AnalysisResult(
                summary="LLM analysis unavailable",
                issues=[],
                recommendations=[],
                severity="unknown",
                confidence=0.0
            )
        
        # Prepare system data for analysis
        system_data = self._format_system_data(command_results)
        
        prompt = f"""
        Analyze the following Linux server system state and provide insights:

        {system_data}

        Please provide:
        1. A brief summary of the system state
        2. Any issues or concerns identified
        3. Recommendations for improvement
        4. Severity level (low/medium/high/critical)
        5. Your confidence in this analysis (0.0-1.0)

        Respond in JSON format with keys: summary, issues, recommendations, severity, confidence
        """
        
        try:
            response = self._call_llm(prompt)
            return self._parse_analysis_response(response)
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return AnalysisResult(
                summary=f"Analysis failed: {str(e)}",
                issues=[],
                recommendations=[],
                severity="unknown",
                confidence=0.0
            )
    
    def suggest_actions(self, issue_description: str, current_state: Dict[str, Any]) -> ActionPlan:
        """Get LLM suggestions for resolving issues with full environment context"""
        return self.suggest_actions_with_placeholders(issue_description, current_state)
    
    def suggest_actions_with_placeholders(self, issue_description: str, current_state: Dict[str, Any]) -> ActionPlan:
        """Enhanced action planning with support for auto-generated placeholders"""
        if not self._client:
            return ActionPlan(
                goal=issue_description,
                steps=[],
                risks=["LLM unavailable"],
                estimated_time="unknown",
                safety_score=0.0
            )
        
        # Extract environment information
        env_info = current_state.get("environment", {})
        
        prompt = f"""
        Create a detailed action plan to resolve this server issue with full environment awareness and auto-generation support:
        
        Issue/Goal: {issue_description}
        
        LINUX ENVIRONMENT DETAILS:
        =========================
        Distribution: {json.dumps(env_info.get('distribution', {}), indent=2)}
        
        Package Managers: {json.dumps(env_info.get('package_manager', {}), indent=2)}
        
        Available Tools: {json.dumps(env_info.get('available_tools', {}), indent=2)}
        
        System Resources: {json.dumps(env_info.get('system_resources', {}), indent=2)}
        
        User Context: {json.dumps(env_info.get('user_context', {}), indent=2)}
        
        Network Info: {json.dumps(env_info.get('network_info', {}), indent=2)}
        
        Current System State: {json.dumps(current_state.get('current_state', {}), indent=2)}
        
        REQUIREMENTS:
        1. Use ONLY the package managers and tools that are actually available on this system
        2. Use distribution-specific package names and commands
        3. Consider the user's permission level (sudo access, current user)
        4. Account for system resources (disk space, memory)
        5. Use appropriate commands for the detected Linux distribution
        6. Use placeholders for values that should be auto-generated
        
        PLACEHOLDER SYSTEM:
        ===================
        For commands that require generated values, use these placeholders:
        - <password> or {{password}} for secure passwords (12+ chars, mixed case, numbers, symbols)
        - <random_string> for random alphanumeric strings
        - <timestamp> for current timestamp
        - <temp_file> for temporary filenames
        - <secure_key> for cryptographic keys
        - <random_port> for available port numbers
        
        COMMAND EXAMPLES WITH PLACEHOLDERS:
        - User creation with password: "useradd username && echo 'username:<password>' | chpasswd"
        - Service with random config: "echo 'config_value=<random_string>' > /etc/service.conf"
        - Backup with timestamp: "tar -czf backup_<timestamp>.tar.gz /data"
        - Log file with timestamp: "command > /var/log/operation_<timestamp>.log"
        - Temporary file: "echo 'data' > /tmp/<temp_file>"
        
        TIMESTAMP FORMAT:
        - <timestamp> generates format: YYYYMMDD_HHMMSS (e.g., 20241116_143022)
        - Use for: backup files, log files, temporary files, unique identifiers
        
        Create an action plan with:
        1. Goal description
        2. Step-by-step commands that work on THIS specific system
        3. Use placeholders where values need to be generated
        4. Potential risks specific to this environment
        5. Estimated time to complete
        6. Safety score (0.0-1.0)
        
        Each step should include:
        - command: exact command with placeholders where needed
        - description: what this command does
        - prerequisite_check: command to verify prerequisites
        - safety_check: verification command
        - auto_generate: list of placeholder types that need generation
        - success_verification: command to verify the step succeeded
        
        CRITICAL: 
        - Ensure all commands are compatible with the detected Linux distribution
        - Use placeholders instead of asking for user input
        - Make commands complete and executable once placeholders are replaced
        
        Respond in JSON format.
        """
        
        try:
            response = self._call_llm(prompt)
            return self._parse_action_plan_with_placeholders(response)
        except Exception as e:
            logger.error(f"Enhanced action planning failed: {e}")
            return ActionPlan(
                goal=issue_description,
                steps=[],
                risks=[f"Planning failed: {str(e)}"],
                estimated_time="unknown",
                safety_score=0.0
            )
    
    def validate_action_plan(self, actions: List[str], current_state: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM to validate if proposed actions are safe/appropriate with robust parsing"""
        if not self._client:
            return {
                "safe": False,
                "reason": "LLM validation unavailable",
                "confidence": 0.0
            }
        
        actions_text = "\n".join(actions)
        state_summary = json.dumps(current_state, indent=2)
        
        prompt = f"""
        Validate these proposed server actions for safety and appropriateness:
        
        Proposed actions:
        {actions_text}
        
        Current system state:
        {state_summary}
        
        Evaluate:
        1. Are these actions safe to execute?
        2. Are they appropriate for the current system state?
        3. What are the potential risks?
        4. Any missing safety checks?
        
        CRITICAL: Respond with ONLY valid JSON, no additional text.
        
        {{
            "safe": true,
            "reason": "explanation",
            "risks": ["list of risks"],
            "confidence": 0.8
        }}
        """
        
        try:
            response = self._call_llm(prompt)
            fallback = {
                "safe": False,
                "reason": "Validation parsing failed",
                "risks": ["Could not parse validation response"],
                "confidence": 0.0
            }
            return self._robust_json_parse(response, fallback)
        except Exception as e:
            logger.error(f"Action validation failed: {e}")
            return {
                "safe": False,
                "reason": f"Validation failed: {str(e)}",
                "confidence": 0.0
            }
    
    def _format_system_data(self, command_results: Dict[str, str]) -> str:
        """Format command results for LLM analysis"""
        formatted = []
        for command, output in command_results.items():
            formatted.append(f"=== {command} ===")
            formatted.append(output[:2000])  # Limit output length
            formatted.append("")
        return "\n".join(formatted)
    
    def _call_llm(self, prompt: str) -> str:
        """Call the configured LLM provider"""
        system_message = "You are a Linux system administrator expert. Provide accurate, safe advice. ALWAYS respond with valid JSON only, no additional text or explanations outside the JSON structure."
        
        if self.provider == LLMProvider.OPENAI and HAS_OPENAI:
            response = self._client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            return response.choices[0].message.content
        
        elif self.provider == LLMProvider.OPENROUTER and HAS_OPENAI:
            response = self._client.chat.completions.create(
                model="anthropic/claude-3.5-sonnet",  # Default to Claude 3.5 Sonnet via OpenRouter
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            return response.choices[0].message.content
        
        elif self.provider == LLMProvider.ANTHROPIC and HAS_ANTHROPIC:
            response = self._client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=2000,
                messages=[
                    {"role": "user", "content": f"{system_message}\n\n{prompt}"}
                ]
            )
            return response.content[0].text
        
        else:
            raise Exception("No LLM provider available")
    
    def _parse_analysis_response(self, response: str) -> AnalysisResult:
        """Parse LLM analysis response with robust error handling"""
        fallback = {
            "summary": "Failed to parse LLM response",
            "issues": [],
            "recommendations": [],
            "severity": "unknown",
            "confidence": 0.0
        }
        
        data = self._robust_json_parse(response, fallback)
        
        return AnalysisResult(
            summary=data.get("summary", ""),
            issues=data.get("issues", []),
            recommendations=data.get("recommendations", []),
            severity=data.get("severity", "unknown"),
            confidence=float(data.get("confidence", 0.0))
        )
    
    def analyze_command_failure(self, command: str, exit_code: int, stderr: str, 
                               system_state: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze why a specific command failed and suggest fixes"""
        if not self._client:
            return {
                "diagnosis": "LLM analysis unavailable",
                "likely_causes": [],
                "suggested_fixes": [],
                "confidence": 0.0
            }
        
        prompt = f"""
        Analyze this failed Linux command and provide diagnostic information:
        
        Command: {command}
        Exit Code: {exit_code}
        Error Output: {stderr}
        
        System Context:
        {json.dumps(system_state, indent=2)}
        
        Provide:
        1. Diagnosis of what went wrong
        2. Most likely causes (in order of probability)
        3. Specific commands/steps to fix the issue
        4. Confidence level in this analysis (0.0-1.0)
        
        Focus on common failure patterns:
        - Package/dependency missing
        - Permission denied
        - Service not running
        - File/directory not found
        - Network/connectivity issues
        - Configuration errors
        
        Respond in JSON format.
        """
        
        try:
            response = self._call_llm(prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"Command failure analysis failed: {e}")
            return {
                "diagnosis": f"Analysis failed: {str(e)}",
                "likely_causes": [],
                "suggested_fixes": [],
                "confidence": 0.0
            }
    
    def _parse_action_plan(self, response: str) -> ActionPlan:
        """Parse LLM action plan response"""
        try:
            data = json.loads(response)
            return ActionPlan(
                goal=data.get("goal", ""),
                steps=data.get("steps", []),
                risks=data.get("risks", []),
                estimated_time=data.get("estimated_time", "unknown"),
                safety_score=float(data.get("safety_score", 0.0))
            )
        except Exception as e:
            logger.error(f"Failed to parse action plan: {e}")
            return ActionPlan(
                goal="Failed to parse plan",
                steps=[],
                risks=[f"Parse error: {str(e)}"],
                estimated_time="unknown",
                safety_score=0.0
            )
    
    def _parse_action_plan_with_placeholders(self, response: str) -> ActionPlan:
        """Parse LLM action plan response with placeholder support and robust error handling"""
        fallback = {
            "goal": "Failed to parse plan",
            "steps": [],
            "risks": ["Parse error"],
            "estimated_time": "unknown",
            "safety_score": 0.0
        }
        
        data = self._robust_json_parse(response, fallback)
        
        # Process steps to ensure they have the required fields
        processed_steps = []
        for step in data.get("steps", []):
            if isinstance(step, dict):
                # Ensure all required fields exist
                processed_step = {
                    "command": step.get("command", ""),
                    "description": step.get("description", ""),
                    "prerequisite_check": step.get("prerequisite_check", ""),
                    "safety_check": step.get("safety_check", ""),
                    "auto_generate": step.get("auto_generate", []),
                    "success_verification": step.get("success_verification", "")
                }
                processed_steps.append(processed_step)
            else:
                # Convert string steps to dict format
                processed_steps.append({
                    "command": str(step),
                    "description": str(step),
                    "prerequisite_check": "",
                    "safety_check": "",
                    "auto_generate": [],
                    "success_verification": ""
                })
        
        return ActionPlan(
            goal=data.get("goal", ""),
            steps=processed_steps,
            risks=data.get("risks", []),
            estimated_time=data.get("estimated_time", "unknown"),
            safety_score=float(data.get("safety_score", 0.0))
        )
    
    def analyze_command_for_missing_info(self, command: str, error_output: str, 
                                       system_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a failed command to identify missing information and suggest fixes"""
        if not self._client:
            return {
                "missing_info": [],
                "corrected_command": command,
                "auto_generate": [],
                "confidence": 0.0
            }
        
        prompt = f"""
        Analyze this failed command to identify missing information and provide a corrected version:
        
        Failed Command: {command}
        Error Output: {error_output}
        
        System Context:
        {json.dumps(system_context, indent=2)[:1000]}
        
        ANALYSIS REQUIRED:
        ==================
        1. What information is missing from the command?
        2. What placeholders should be used for auto-generation?
        3. What is the corrected command with proper placeholders?
        4. How confident are you in this analysis?
        
        PLACEHOLDER TYPES:
        ==================
        - <password> for secure passwords
        - <random_string> for random alphanumeric strings  
        - <timestamp> for current timestamp
        - <temp_file> for temporary filenames
        - <secure_key> for cryptographic keys
        - <random_port> for available port numbers
        
        COMMON PATTERNS:
        ================
        - "passwd username" → "echo 'username:<password>' | chpasswd"
        - "useradd user" → "useradd user && echo 'user:<password>' | chpasswd"
        - "mysql -p" → "mysql -p<password>"
        - "openssl genrsa" → "openssl genrsa -out key_<timestamp>.pem 2048"
        
        CRITICAL: Respond with ONLY valid JSON, no additional text or explanations.
        
        {{
            "missing_info": ["list of missing information types"],
            "corrected_command": "command with placeholders",
            "auto_generate": ["list of placeholder types to generate"],
            "explanation": "why the original command failed",
            "confidence": 0.8
        }}
        """
        
        try:
            response = self._call_llm(prompt)
            # Clean the response to extract only the JSON part
            cleaned_response = self._extract_json_from_response(response)
            return json.loads(cleaned_response)
        except Exception as e:
            logger.error(f"Command analysis failed: {e}")
            return {
                "missing_info": [],
                "corrected_command": command,
                "auto_generate": [],
                "explanation": f"Analysis failed: {str(e)}",
                "confidence": 0.0
            }
    
    def _extract_json_from_response(self, response: str) -> str:
        """Extract JSON from LLM response that might contain extra text"""
        try:
            # Try to find JSON object boundaries
            start_idx = response.find('{')
            if start_idx == -1:
                raise ValueError("No JSON object found in response")
            
            # Find the matching closing brace
            brace_count = 0
            end_idx = start_idx
            
            for i, char in enumerate(response[start_idx:], start_idx):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break
            
            if brace_count != 0:
                raise ValueError("Unmatched braces in JSON response")
            
            json_str = response[start_idx:end_idx]
            
            # Validate that it's proper JSON
            json.loads(json_str)  # This will raise an exception if invalid
            
            return json_str
            
        except Exception as e:
            logger.warning(f"Failed to extract JSON from response: {e}")
            # Return a fallback JSON structure
            return json.dumps({
                "missing_info": [],
                "corrected_command": "echo 'JSON extraction failed'",
                "auto_generate": [],
                "explanation": f"Failed to parse LLM response: {str(e)}",
                "confidence": 0.0
            })
    
    def _robust_json_parse(self, response: str, fallback_data: Dict[str, Any]) -> Dict[str, Any]:
        """Robustly parse JSON response with fallback"""
        try:
            # First try direct parsing
            return json.loads(response)
        except json.JSONDecodeError:
            try:
                # Try extracting JSON from response
                cleaned_response = self._extract_json_from_response(response)
                return json.loads(cleaned_response)
            except Exception as e:
                logger.warning(f"Failed to parse JSON response: {e}")
                logger.debug(f"Raw response: {response[:500]}...")
                return fallback_data
