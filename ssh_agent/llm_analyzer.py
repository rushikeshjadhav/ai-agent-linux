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
        """Get LLM suggestions for resolving issues"""
        if not self._client:
            return ActionPlan(
                goal=issue_description,
                steps=[],
                risks=["LLM unavailable"],
                estimated_time="unknown",
                safety_score=0.0
            )
        
        state_summary = json.dumps(current_state, indent=2)
        
        prompt = f"""
        Create an action plan to resolve this server issue:
        
        Issue: {issue_description}
        
        Current system state:
        {state_summary}
        
        Provide a detailed action plan with:
        1. Goal description
        2. Step-by-step commands with explanations
        3. Potential risks
        4. Estimated time to complete
        5. Safety score (0.0-1.0, where 1.0 is completely safe)
        
        Each step should include:
        - command: the exact command to run
        - description: what this command does
        - safety_check: any verification to do before/after
        
        Respond in JSON format.
        """
        
        try:
            response = self._call_llm(prompt)
            return self._parse_action_plan(response)
        except Exception as e:
            logger.error(f"Action planning failed: {e}")
            return ActionPlan(
                goal=issue_description,
                steps=[],
                risks=[f"Planning failed: {str(e)}"],
                estimated_time="unknown",
                safety_score=0.0
            )
    
    def validate_action_plan(self, actions: List[str], current_state: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM to validate if proposed actions are safe/appropriate"""
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
        
        Respond in JSON format with keys: safe (boolean), reason (string), risks (array), confidence (float 0.0-1.0)
        """
        
        try:
            response = self._call_llm(prompt)
            return json.loads(response)
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
        if self.provider == LLMProvider.OPENAI and HAS_OPENAI:
            response = self._client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a Linux system administrator expert. Provide accurate, safe advice."},
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
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        
        else:
            raise Exception("No LLM provider available")
    
    def _parse_analysis_response(self, response: str) -> AnalysisResult:
        """Parse LLM analysis response"""
        try:
            data = json.loads(response)
            return AnalysisResult(
                summary=data.get("summary", ""),
                issues=data.get("issues", []),
                recommendations=data.get("recommendations", []),
                severity=data.get("severity", "unknown"),
                confidence=float(data.get("confidence", 0.0))
            )
        except Exception as e:
            logger.error(f"Failed to parse analysis response: {e}")
            return AnalysisResult(
                summary="Failed to parse LLM response",
                issues=[],
                recommendations=[],
                severity="unknown",
                confidence=0.0
            )
    
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
