import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from .executor import CommandExecutor, CommandResult
from .llm_analyzer import ServerStateAnalyzer, ActionPlan
from .context_manager import ServerContext

logger = logging.getLogger(__name__)

@dataclass
class FailureContext:
    """Context for tracking failures and recovery attempts"""
    original_error: str
    failed_command: str
    attempt_number: int
    recovery_plan: Optional[ActionPlan] = None
    llm_analysis: Optional[str] = None

@dataclass
class TaskResult:
    """Result of executing a complex task"""
    task_description: str
    success: bool
    steps_completed: int
    total_steps: int
    results: List[CommandResult]
    error_message: Optional[str] = None
    failure_contexts: List[FailureContext] = None
    recovery_attempts: int = 0

@dataclass
class ServiceResult:
    """Result of service management operation"""
    service_name: str
    action: str
    success: bool
    previous_state: str
    current_state: str
    message: str

@dataclass
class PackageResult:
    """Result of package management operation"""
    packages: List[str]
    action: str
    success: bool
    installed: List[str]
    failed: List[str]
    message: str

class SmartExecutor:
    """Executes complex tasks using LLM planning"""
    
    def __init__(self, executor: CommandExecutor, analyzer: ServerStateAnalyzer, context: ServerContext):
        self.executor = executor
        self.analyzer = analyzer
        self.context = context
        self.max_recovery_attempts = 2
        self.failure_contexts: List[FailureContext] = []
    
    def execute_task(self, task_description: str, auto_approve: bool = False) -> TaskResult:
        """Break down complex tasks into commands using LLM with recursive failure recovery"""
        logger.info(f"Starting smart task execution: {task_description}")
        
        # Reset failure contexts for new task
        self.failure_contexts = []
        recovery_attempts = 0
        original_task = task_description
        
        # Initial execution attempt
        result = self._execute_task_attempt(task_description, auto_approve)
        
        # Recursive recovery loop
        while not result.success and recovery_attempts < self.max_recovery_attempts:
            recovery_attempts += 1
            logger.info(f"Attempting failure recovery {recovery_attempts}/{self.max_recovery_attempts}")
            
            # Analyze the specific failure
            if result.results:
                failed_command = result.results[-1]
                failure_analysis = self._analyze_command_failure(failed_command, original_task)
                logger.info(f"Failure analysis: {failure_analysis}")
            
            # Get failure recovery plan from LLM
            recovery_plan = self._get_failure_recovery_plan(result, original_task)
            
            if recovery_plan and recovery_plan.steps:
                # Create failure context
                failure_context = FailureContext(
                    original_error=result.error_message or "Unknown error",
                    failed_command=result.results[-1].command if result.results else "Unknown command",
                    attempt_number=recovery_attempts,
                    recovery_plan=recovery_plan,
                    llm_analysis=f"Recovery attempt {recovery_attempts}: {failure_analysis.get('failure_type', 'unknown') if result.results else 'unknown'}"
                )
                self.failure_contexts.append(failure_context)
                
                # Execute recovery plan
                recovery_result = self._execute_recovery_plan(recovery_plan, auto_approve)
                
                # If recovery succeeded, retry original task
                if recovery_result.success:
                    logger.info("Recovery successful, retrying original task")
                    result = self._execute_task_attempt(original_task, auto_approve)
                else:
                    logger.warning(f"Recovery attempt {recovery_attempts} failed")
                    
                    # If this was a "command not found" that couldn't be fixed,
                    # try to revise the original task to work without that command
                    if (recovery_attempts == self.max_recovery_attempts and 
                        result.results and
                        self._analyze_command_failure(result.results[-1], original_task).get("failure_type") == "command_not_found"):
                        
                        logger.info("Attempting task revision to work without missing command")
                        revised_task = self._revise_task_without_command(
                            original_task, 
                            result.results[-1].command.split()[0] if result.results else "unknown"
                        )
                        
                        if revised_task != original_task:
                            logger.info(f"Revised task: {revised_task}")
                            result = self._execute_task_attempt(revised_task, auto_approve)
                            break
            else:
                logger.error("No recovery plan generated, stopping attempts")
                break
        
        # Update result with recovery information
        result.failure_contexts = self.failure_contexts
        result.recovery_attempts = recovery_attempts
        
        return result
    
    def _execute_task_attempt(self, task_description: str, auto_approve: bool = False) -> TaskResult:
        """Execute a single task attempt"""
        # Get current system state
        current_state = self.context.get_current_state()
        
        # Get LLM action plan
        action_plan = self.analyzer.suggest_actions(task_description, current_state)
        
        if not action_plan.steps:
            return TaskResult(
                task_description=task_description,
                success=False,
                steps_completed=0,
                total_steps=0,
                results=[],
                error_message="No action plan generated"
            )
        
        # Extract commands for validation
        commands = []
        for step in action_plan.steps:
            if isinstance(step, dict):
                commands.append(step.get("command", ""))
            else:
                commands.append(str(step))
        
        # Validate action plan safety
        validation = self.analyzer.validate_action_plan(commands, current_state)
        
        if not validation.get("safe", False) and not auto_approve:
            return TaskResult(
                task_description=task_description,
                success=False,
                steps_completed=0,
                total_steps=len(action_plan.steps),
                results=[],
                error_message=f"Action plan not safe: {validation.get('reason', 'Unknown reason')}"
            )
        
        # Execute steps
        results = []
        completed_steps = 0
        
        for i, step in enumerate(action_plan.steps):
            # Handle both string and dict step formats
            if isinstance(step, dict):
                command = step.get("command", "")
                description = step.get("description", "")
            else:
                command = str(step)
                description = command
            
            logger.info(f"Executing step {i+1}/{len(action_plan.steps)}: {description}")
            
            if not command:
                logger.warning(f"Step {i+1} has no command, skipping")
                continue
            
            # Execute command
            result = self.executor.execute(command)
            results.append(result)
            
            # Update context
            self.context.update_context(command, result)
            
            if not result.allowed:
                logger.error(f"Step {i+1} blocked: {result.reason}")
                return TaskResult(
                    task_description=task_description,
                    success=False,
                    steps_completed=completed_steps,
                    total_steps=len(action_plan.steps),
                    results=results,
                    error_message=f"Command blocked: {result.reason}"
                )
            
            if result.exit_code != 0:
                logger.error(f"Step {i+1} failed with exit code {result.exit_code}")
                return TaskResult(
                    task_description=task_description,
                    success=False,
                    steps_completed=completed_steps,
                    total_steps=len(action_plan.steps),
                    results=results,
                    error_message=f"Command failed: {command} - {result.stderr}"
                )
            
            completed_steps += 1
        
        return TaskResult(
            task_description=task_description,
            success=True,
            steps_completed=completed_steps,
            total_steps=len(action_plan.steps),
            results=results
        )
    
    def _get_failure_recovery_plan(self, failed_result: TaskResult, original_task: str) -> Optional[ActionPlan]:
        """Get LLM-generated recovery plan for failed task with specific failure analysis"""
        if not failed_result.results:
            return None
        
        # Get the failed command and analyze it
        failed_command_result = failed_result.results[-1]
        failure_analysis = self._analyze_command_failure(failed_command_result, original_task)
        
        # Get current system state
        current_state = self.context.get_current_state()
        
        # Create a comprehensive prompt based on failure type
        if failure_analysis["failure_type"] == "command_not_found":
            prompt = self._create_command_not_found_prompt(
                original_task, failed_command_result, failure_analysis, current_state
            )
        elif failure_analysis["failure_type"] == "package_not_available":
            prompt = self._create_package_not_available_prompt(
                original_task, failed_command_result, failure_analysis, current_state
            )
        else:
            prompt = self._create_generic_failure_prompt(
                original_task, failed_command_result, failure_analysis, current_state
            )
        
        try:
            response = self.analyzer._call_llm(prompt)
            recovery_plan = self.analyzer._parse_action_plan(response)
            
            # If recovery plan fails, create fallback plan
            if not recovery_plan.steps:
                return self._create_fallback_plan(original_task, failure_analysis)
            
            return recovery_plan
            
        except Exception as e:
            logger.error(f"Failed to get recovery plan: {e}")
            return self._create_fallback_plan(original_task, failure_analysis)
    
    def _execute_recovery_plan(self, recovery_plan: ActionPlan, auto_approve: bool = False) -> TaskResult:
        """Execute the LLM-generated recovery plan"""
        logger.info(f"Executing recovery plan: {recovery_plan.goal}")
        
        results = []
        completed_steps = 0
        
        for i, step in enumerate(recovery_plan.steps):
            if isinstance(step, dict):
                command = step.get("command", "")
                description = step.get("description", "Recovery step")
            else:
                command = str(step)
                description = command
            
            logger.info(f"Recovery step {i+1}/{len(recovery_plan.steps)}: {description}")
            
            if not command:
                continue
            
            # Execute recovery command
            result = self.executor.execute(command)
            results.append(result)
            self.context.update_context(command, result)
            
            if not result.allowed or result.exit_code != 0:
                logger.warning(f"Recovery step {i+1} failed: {result.stderr or result.reason}")
                # Continue with other recovery steps even if one fails
                continue
            
            completed_steps += 1
        
        success = completed_steps > 0  # Consider partial recovery as success
        
        return TaskResult(
            task_description=f"Recovery: {recovery_plan.goal}",
            success=success,
            steps_completed=completed_steps,
            total_steps=len(recovery_plan.steps),
            results=results,
            error_message=None if success else "Recovery plan failed"
        )
    
    def manage_service(self, service_name: str, action: str) -> ServiceResult:
        """Intelligent service management"""
        logger.info(f"Managing service {service_name}: {action}")
        
        # Get current service status
        status_result = self.executor.execute(f"systemctl status {service_name}")
        previous_state = self._parse_service_state(status_result.stdout)
        
        # Determine appropriate command
        if action == "start":
            command = f"systemctl start {service_name}"
        elif action == "stop":
            command = f"systemctl stop {service_name}"
        elif action == "restart":
            command = f"systemctl restart {service_name}"
        elif action == "enable":
            command = f"systemctl enable {service_name}"
        elif action == "disable":
            command = f"systemctl disable {service_name}"
        else:
            return ServiceResult(
                service_name=service_name,
                action=action,
                success=False,
                previous_state=previous_state,
                current_state=previous_state,
                message=f"Unknown action: {action}"
            )
        
        # Execute service command
        result = self.executor.execute(command)
        
        # Check new status
        new_status_result = self.executor.execute(f"systemctl status {service_name}")
        current_state = self._parse_service_state(new_status_result.stdout)
        
        # Update context
        self.context.update_context(command, result)
        
        success = result.allowed and result.exit_code == 0
        message = "Success" if success else f"Failed: {result.stderr or result.reason}"
        
        return ServiceResult(
            service_name=service_name,
            action=action,
            success=success,
            previous_state=previous_state,
            current_state=current_state,
            message=message
        )
    
    def manage_packages(self, packages: List[str], action: str) -> PackageResult:
        """Smart package management with dependency handling"""
        logger.info(f"Managing packages {packages}: {action}")
        
        installed = []
        failed = []
        
        # Detect package manager
        pkg_manager = self._detect_package_manager()
        
        if not pkg_manager:
            return PackageResult(
                packages=packages,
                action=action,
                success=False,
                installed=[],
                failed=packages,
                message="No supported package manager found"
            )
        
        for package in packages:
            if action == "install":
                if pkg_manager == "apt":
                    command = f"apt-get install -y {package}"
                elif pkg_manager == "yum":
                    command = f"yum install -y {package}"
                elif pkg_manager == "dnf":
                    command = f"dnf install -y {package}"
                else:
                    failed.append(package)
                    continue
            
            elif action == "remove":
                if pkg_manager == "apt":
                    command = f"apt-get remove -y {package}"
                elif pkg_manager == "yum":
                    command = f"yum remove -y {package}"
                elif pkg_manager == "dnf":
                    command = f"dnf remove -y {package}"
                else:
                    failed.append(package)
                    continue
            
            else:
                failed.append(package)
                continue
            
            # Execute package command
            result = self.executor.execute(command)
            self.context.update_context(command, result)
            
            if result.allowed and result.exit_code == 0:
                installed.append(package)
            else:
                failed.append(package)
        
        success = len(failed) == 0
        message = f"Installed: {len(installed)}, Failed: {len(failed)}"
        
        return PackageResult(
            packages=packages,
            action=action,
            success=success,
            installed=installed,
            failed=failed,
            message=message
        )
    
    def _parse_service_state(self, systemctl_output: str) -> str:
        """Parse systemctl status output to determine service state"""
        if "active (running)" in systemctl_output:
            return "running"
        elif "inactive (dead)" in systemctl_output:
            return "stopped"
        elif "failed" in systemctl_output:
            return "failed"
        elif "activating" in systemctl_output:
            return "starting"
        else:
            return "unknown"
    
    def _detect_package_manager(self) -> Optional[str]:
        """Detect available package manager"""
        managers = ["apt-get", "yum", "dnf", "pacman"]
        
        for manager in managers:
            result = self.executor.execute(f"which {manager}")
            if result.allowed and result.exit_code == 0:
                return manager.replace("-get", "")  # Return "apt" instead of "apt-get"
        
        return None
    
    def _analyze_command_failure(self, failed_result: CommandResult, original_task: str) -> Dict[str, Any]:
        """Analyze specific command failure and determine recovery strategy"""
        command = failed_result.command
        stderr = failed_result.stderr
        exit_code = failed_result.exit_code
        
        # Check for common failure patterns
        failure_analysis = {
            "failure_type": "unknown",
            "missing_package": None,
            "recovery_strategy": "retry",
            "alternative_commands": []
        }
        
        # Command not found
        if "command not found" in stderr or "not found" in stderr or exit_code == 127:
            failure_analysis["failure_type"] = "command_not_found"
            # Extract the missing command
            missing_cmd = command.split()[0]
            failure_analysis["missing_package"] = self._guess_package_for_command(missing_cmd)
            failure_analysis["recovery_strategy"] = "install_package"
        
        # Permission denied
        elif "permission denied" in stderr.lower() or exit_code == 126:
            failure_analysis["failure_type"] = "permission_denied"
            failure_analysis["recovery_strategy"] = "add_sudo"
        
        # Package not available
        elif "unable to locate package" in stderr.lower() or "no package" in stderr.lower():
            failure_analysis["failure_type"] = "package_not_available"
            failure_analysis["recovery_strategy"] = "find_alternative"
        
        # Service not found
        elif "unit not found" in stderr.lower() or "service not found" in stderr.lower():
            failure_analysis["failure_type"] = "service_not_found"
            failure_analysis["recovery_strategy"] = "find_alternative_service"
        
        return failure_analysis

    def _guess_package_for_command(self, command: str) -> Optional[str]:
        """Guess the package name for a missing command"""
        # Common command to package mappings
        command_packages = {
            "curl": "curl",
            "wget": "wget", 
            "git": "git",
            "vim": "vim",
            "nano": "nano",
            "htop": "htop",
            "tree": "tree",
            "unzip": "unzip",
            "zip": "zip",
            "docker": "docker.io",
            "nginx": "nginx",
            "apache2": "apache2",
            "mysql": "mysql-server",
            "python3": "python3",
            "pip": "python3-pip",
            "node": "nodejs",
            "npm": "npm",
            "java": "default-jdk",
            "gcc": "build-essential",
            "make": "build-essential"
        }
        
        return command_packages.get(command, command)

    def _create_command_not_found_prompt(self, original_task: str, failed_result: CommandResult, 
                                       failure_analysis: Dict[str, Any], current_state: Dict[str, Any]) -> str:
        """Create specific prompt for command not found errors"""
        missing_package = failure_analysis.get("missing_package", "unknown")
        
        return f"""
        COMMAND NOT FOUND ERROR - Need Recovery Plan
        
        Original Task: {original_task}
        Failed Command: {failed_result.command}
        Error: {failed_result.stderr}
        
        Analysis: The command '{failed_result.command.split()[0]}' was not found.
        Likely missing package: {missing_package}
        
        Current System State:
        - Package Manager: {current_state.get('known_packages', {}).get('manager', 'unknown')}
        - System Info: {json.dumps(current_state.get('current_state', {}), indent=2)[:500]}
        
        Create a recovery plan that:
        1. First tries to install the missing package ({missing_package})
        2. If installation fails, finds alternative commands/packages
        3. If no alternatives work, revises the original task to work without this tool
        4. Includes verification steps to ensure each step works
        
        IMPORTANT: 
        - Include package installation commands (apt install, yum install, etc.)
        - Include alternative approaches if the package doesn't exist
        - Include a fallback plan that accomplishes the original goal differently
        
        Example recovery steps:
        1. Update package lists: "apt update" or "yum update"
        2. Install package: "apt install -y {missing_package}" or "yum install -y {missing_package}"
        3. Verify installation: "which {failed_result.command.split()[0]}"
        4. If still fails, try alternative: [suggest alternative commands]
        5. If no alternatives, modify approach: [suggest different way to achieve goal]
        
        Respond in JSON format with detailed steps.
        """

    def _create_package_not_available_prompt(self, original_task: str, failed_result: CommandResult,
                                           failure_analysis: Dict[str, Any], current_state: Dict[str, Any]) -> str:
        """Create prompt for package not available errors"""
        return f"""
        PACKAGE NOT AVAILABLE ERROR - Need Alternative Approach
        
        Original Task: {original_task}
        Failed Command: {failed_result.command}
        Error: {failed_result.stderr}
        
        Analysis: The requested package is not available in the current repositories.
        
        Current System State:
        {json.dumps(current_state, indent=2)[:1000]}
        
        Create a recovery plan that:
        1. Tries alternative package names or repositories
        2. Uses different tools to achieve the same goal
        3. Modifies the original approach to work without this specific package
        
        Focus on:
        - Alternative package names (e.g., docker vs docker.io vs docker-ce)
        - Different tools that provide similar functionality
        - Built-in system tools that can accomplish the same task
        - Manual installation methods if appropriate
        
        CRITICAL: If no package alternatives work, completely revise the approach to the original task.
        
        Respond in JSON format with a comprehensive alternative plan.
        """

    def _create_generic_failure_prompt(self, original_task: str, failed_result: CommandResult,
                                     failure_analysis: Dict[str, Any], current_state: Dict[str, Any]) -> str:
        """Create prompt for other types of failures"""
        return f"""
        COMMAND EXECUTION FAILED - Need Recovery Plan
        
        Original Task: {original_task}
        Failed Command: {failed_result.command}
        Exit Code: {failed_result.exit_code}
        Error: {failed_result.stderr}
        Failure Type: {failure_analysis['failure_type']}
        
        Current System State:
        {json.dumps(current_state, indent=2)[:1000]}
        
        Analyze the failure and create a recovery plan that:
        1. Addresses the specific cause of failure
        2. Includes prerequisite checks and fixes
        3. Provides alternative approaches if the direct fix doesn't work
        4. Ensures the original goal can still be achieved
        
        Consider common issues:
        - Permission problems (add sudo, change ownership)
        - Missing dependencies (install required packages)
        - Service issues (start/restart services)
        - Configuration problems (fix config files)
        - Network issues (check connectivity, DNS)
        
        Respond in JSON format with a detailed recovery plan.
        """

    def _create_fallback_plan(self, original_task: str, failure_analysis: Dict[str, Any]) -> ActionPlan:
        """Create a basic fallback plan when LLM consultation fails"""
        fallback_steps = []
        
        if failure_analysis["failure_type"] == "command_not_found":
            missing_package = failure_analysis.get("missing_package", "unknown")
            fallback_steps = [
                {
                    "command": "apt update || yum update || true",
                    "description": "Update package lists"
                },
                {
                    "command": f"apt install -y {missing_package} || yum install -y {missing_package} || echo 'Package installation failed'",
                    "description": f"Try to install {missing_package}"
                },
                {
                    "command": f"which {missing_package} || echo 'Command still not available, need alternative approach'",
                    "description": "Verify installation"
                }
            ]
        else:
            fallback_steps = [
                {
                    "command": "echo 'Attempting basic recovery'",
                    "description": "Basic fallback attempt"
                }
            ]
        
        return ActionPlan(
            goal=f"Fallback recovery for: {original_task}",
            steps=fallback_steps,
            risks=["Fallback plan - limited recovery capability"],
            estimated_time="2-5 minutes",
            safety_score=0.7
        )

    def _revise_task_without_command(self, original_task: str, missing_command: str) -> str:
        """Use LLM to revise the task to work without a specific command"""
        prompt = f"""
        The original task cannot be completed because the command '{missing_command}' is not available and cannot be installed.
        
        Original Task: {original_task}
        Missing Command: {missing_command}
        
        Revise the task to accomplish the same goal using:
        1. Built-in system commands only
        2. Alternative approaches that don't require {missing_command}
        3. Different tools that are commonly available
        
        Provide a revised task description that achieves the same end goal.
        Respond with just the revised task description, no explanation.
        """
        
        try:
            revised_task = self.analyzer._call_llm(prompt).strip()
            return revised_task if revised_task else original_task
        except Exception as e:
            logger.error(f"Task revision failed: {e}")
            return original_task

    def _detect_and_update_package_manager(self):
        """Detect package manager and update system state"""
        pkg_managers = [
            ("apt-get", "apt"),
            ("yum", "yum"), 
            ("dnf", "dnf"),
            ("pacman", "pacman"),
            ("zypper", "zypper")
        ]
        
        for cmd, manager in pkg_managers:
            result = self.executor.execute(f"which {cmd}")
            if result.allowed and result.exit_code == 0:
                # Update context with package manager info
                current_state = self.context.get_current_state()
                current_state["package_manager"] = manager
                logger.info(f"Detected package manager: {manager}")
                return manager
        
        logger.warning("No supported package manager detected")
        return None
