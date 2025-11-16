import logging
from typing import Optional, Union, Dict, List
from pathlib import Path
from .connection import SSHConnection
from .executor import CommandExecutor, CommandResult
from .modes import AgentMode
from .llm_analyzer import ServerStateAnalyzer, AnalysisResult, LLMProvider
from .context_manager import ServerContext
from .smart_executor import SmartExecutor, TaskResult, ServiceResult, PackageResult

logger = logging.getLogger(__name__)

class SSHAgent:
    """Main SSH Agent class that combines connection, mode, and execution"""
    
    def __init__(self, hostname: str, username: str, mode: AgentMode = AgentMode.READ_ONLY, port: int = 22, 
                 llm_provider: LLMProvider = LLMProvider.OPENAI, llm_api_key: Optional[str] = None):
        self.hostname = hostname
        self.username = username
        self.mode = mode
        self.port = port
        
        self.connection = SSHConnection(hostname, username, port)
        self.executor: Optional[CommandExecutor] = None
        self.analyzer = ServerStateAnalyzer(llm_provider, llm_api_key)
        self.context = ServerContext()
        self.smart_executor: Optional[SmartExecutor] = None
        self.connected = False
    
    def connect_with_key(self, key_path: Union[str, Path], passphrase: Optional[str] = None) -> bool:
        """Connect using SSH key authentication"""
        success = self.connection.connect_with_key(key_path, passphrase)
        if success:
            self.executor = CommandExecutor(self.connection, self.mode)
            self.smart_executor = SmartExecutor(self.executor, self.analyzer, self.context)
            self.connected = True
        return success
    
    def connect_with_password(self, password: str) -> bool:
        """Connect using password authentication"""
        success = self.connection.connect_with_password(password)
        if success:
            self.executor = CommandExecutor(self.connection, self.mode)
            self.smart_executor = SmartExecutor(self.executor, self.analyzer, self.context)
            self.connected = True
        return success
    
    def execute_command(self, command: str, timeout: int = 30) -> CommandResult:
        """Execute a command on the remote host"""
        if not self.connected or not self.executor:
            return CommandResult(
                stdout="",
                stderr="Agent not connected",
                exit_code=-1,
                command=command,
                allowed=False,
                reason="Not connected"
            )
        
        result = self.executor.execute(command, timeout)
        self.context.update_context(command, result)
        return result
    
    def set_mode(self, mode: AgentMode):
        """Change the agent mode"""
        self.mode = mode
        if self.executor:
            self.executor = CommandExecutor(self.connection, self.mode)
            self.smart_executor = SmartExecutor(self.executor, self.analyzer, self.context)
        logger.info(f"Agent mode changed to {mode.value}")
    
    def analyze_server_health(self) -> AnalysisResult:
        """Collect system info and analyze with LLM"""
        if not self.connected or not self.executor:
            return AnalysisResult(
                summary="Agent not connected",
                issues=[],
                recommendations=[],
                severity="unknown",
                confidence=0.0
            )
        
        # Collect system health data
        health_commands = self.context.get_system_health_commands()
        command_results = {}
        
        for command in health_commands:
            result = self.executor.execute(command)
            if result.allowed and result.exit_code == 0:
                command_results[command] = result.stdout
            self.context.update_context(command, result)
        
        # Create system snapshot
        self.context.create_system_snapshot(command_results)
        
        # Analyze with LLM
        analysis = self.analyzer.analyze_system_state(command_results)
        self.context.update_analysis(analysis.__dict__)
        
        return analysis
    
    def diagnose_issue(self, problem_description: str) -> Dict:
        """Use LLM to diagnose and suggest solutions"""
        if not self.connected:
            return {"error": "Agent not connected"}
        
        current_state = self.context.get_current_state()
        action_plan = self.analyzer.suggest_actions(problem_description, current_state)
        
        return {
            "problem": problem_description,
            "action_plan": action_plan,
            "current_state_summary": self.context.get_context_summary()
        }
    
    def execute_smart_action(self, goal: str, auto_approve: bool = False) -> TaskResult:
        """Let LLM plan and execute a series of commands to achieve a goal"""
        if not self.connected or not self.smart_executor:
            return TaskResult(
                task_description=goal,
                success=False,
                steps_completed=0,
                total_steps=0,
                results=[],
                error_message="Agent not connected"
            )
        
        return self.smart_executor.execute_task(goal, auto_approve)
    
    def manage_service(self, service_name: str, action: str) -> ServiceResult:
        """Intelligent service management"""
        if not self.connected or not self.smart_executor:
            return ServiceResult(
                service_name=service_name,
                action=action,
                success=False,
                previous_state="unknown",
                current_state="unknown",
                message="Agent not connected"
            )
        
        return self.smart_executor.manage_service(service_name, action)
    
    def manage_packages(self, packages: List[str], action: str) -> PackageResult:
        """Smart package management with dependency handling"""
        if not self.connected or not self.smart_executor:
            return PackageResult(
                packages=packages,
                action=action,
                success=False,
                installed=[],
                failed=packages,
                message="Agent not connected"
            )
        
        return self.smart_executor.manage_packages(packages, action)
    
    def get_context_summary(self) -> str:
        """Get a summary of current server context"""
        return self.context.get_context_summary()
    
    def disconnect(self):
        """Disconnect from remote host"""
        self.connection.disconnect()
        self.executor = None
        self.smart_executor = None
        self.connected = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
    
    def __repr__(self):
        status = "connected" if self.connected else "disconnected"
        return f"SSHAgent({self.username}@{self.hostname}:{self.port}, mode={self.mode.value}, {status})"
