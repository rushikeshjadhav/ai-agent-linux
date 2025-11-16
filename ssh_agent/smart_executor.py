import json
import logging
import os
import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
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
    skipped_steps: List[Dict[str, Any]] = None

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
        
        # Environment caching settings
        self.cache_ttl_minutes = 30  # Cache valid for 30 minutes
        self.cache_dir = Path.home() / ".ssh_agent_cache"
        self.cache_dir.mkdir(exist_ok=True)
        self._environment_cache = None
        self._cache_timestamp = None
    
    def _get_cached_environment_info(self) -> Optional[Dict[str, Any]]:
        """Get cached environment info if still valid"""
        if self._environment_cache and self._cache_timestamp:
            age = datetime.now() - self._cache_timestamp
            if age < timedelta(minutes=self.cache_ttl_minutes):
                logger.debug("Using cached environment info")
                return self._environment_cache
        
        # Try to load from disk cache
        cached_data = self._load_environment_cache()
        if cached_data:
            self._environment_cache = cached_data
            self._cache_timestamp = datetime.now()
            logger.debug("Loaded environment info from disk cache")
            return cached_data
        
        return None
    
    def _save_environment_cache(self, env_info: Dict[str, Any]):
        """Save environment info to cache"""
        try:
            # Create cache key based on connection details
            connection_key = f"{self.executor.connection.hostname}_{self.executor.connection.username}_{self.executor.connection.port}"
            cache_file = self.cache_dir / f"env_{hashlib.md5(connection_key.encode()).hexdigest()}.json"
            
            cache_data = {
                "timestamp": datetime.now().isoformat(),
                "connection_key": connection_key,
                "environment_info": env_info
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Update memory cache
            self._environment_cache = env_info
            self._cache_timestamp = datetime.now()
            
            logger.debug(f"Saved environment cache to {cache_file}")
            
        except Exception as e:
            logger.warning(f"Failed to save environment cache: {e}")
    
    def _load_environment_cache(self) -> Optional[Dict[str, Any]]:
        """Load environment info from disk cache if valid"""
        try:
            connection_key = f"{self.executor.connection.hostname}_{self.executor.connection.username}_{self.executor.connection.port}"
            cache_file = self.cache_dir / f"env_{hashlib.md5(connection_key.encode()).hexdigest()}.json"
            
            if not cache_file.exists():
                return None
            
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Check if cache is still valid
            cache_time = datetime.fromisoformat(cache_data["timestamp"])
            age = datetime.now() - cache_time
            
            if age < timedelta(minutes=self.cache_ttl_minutes):
                # Verify connection key matches
                if cache_data.get("connection_key") == connection_key:
                    return cache_data["environment_info"]
            
            # Cache expired or invalid, remove it
            cache_file.unlink()
            return None
            
        except Exception as e:
            logger.warning(f"Failed to load environment cache: {e}")
            return None
    
    def _invalidate_environment_cache(self):
        """Invalidate the current environment cache"""
        self._environment_cache = None
        self._cache_timestamp = None
        
        try:
            connection_key = f"{self.executor.connection.hostname}_{self.executor.connection.username}_{self.executor.connection.port}"
            cache_file = self.cache_dir / f"env_{hashlib.md5(connection_key.encode()).hexdigest()}.json"
            
            if cache_file.exists():
                cache_file.unlink()
                logger.debug("Invalidated environment cache")
                
        except Exception as e:
            logger.warning(f"Failed to invalidate environment cache: {e}")
    
    def _collect_comprehensive_environment_info(self) -> Dict[str, Any]:
        """Collect comprehensive Linux environment information for LLM planning with caching"""
        # Try to get cached info first
        cached_info = self._get_cached_environment_info()
        if cached_info:
            return cached_info
        
        logger.info("Collecting fresh environment information...")
        
        env_info = {
            "distribution": {},
            "package_manager": {},
            "available_tools": {},
            "system_resources": {},
            "network_info": {},
            "user_context": {},
            "filesystem_info": {}
        }
        
        # Distribution information
        dist_commands = [
            ("os_release", "cat /etc/os-release"),
            ("lsb_release", "lsb_release -a 2>/dev/null || echo 'lsb_release not available'"),
            ("redhat_release", "cat /etc/redhat-release 2>/dev/null || echo 'not redhat'"),
            ("debian_version", "cat /etc/debian_version 2>/dev/null || echo 'not debian'"),
            ("kernel", "uname -r"),
            ("architecture", "uname -m")
        ]
        
        for key, cmd in dist_commands:
            result = self.executor.execute(cmd)
            if result.allowed and result.exit_code == 0:
                env_info["distribution"][key] = result.stdout.strip()
        
        # Package manager detection and info
        pkg_managers = [
            ("apt", "apt --version 2>/dev/null"),
            ("yum", "yum --version 2>/dev/null"),
            ("dnf", "dnf --version 2>/dev/null"),
            ("pacman", "pacman --version 2>/dev/null"),
            ("zypper", "zypper --version 2>/dev/null"),
            ("apk", "apk --version 2>/dev/null")
        ]
        
        for manager, cmd in pkg_managers:
            result = self.executor.execute(cmd)
            if result.allowed and result.exit_code == 0:
                env_info["package_manager"][manager] = {
                    "available": True,
                    "version": result.stdout.strip()[:100]
                }
                # Get repository info for available package managers
                if manager == "apt":
                    repo_result = self.executor.execute("apt-cache policy | head -20")
                    if repo_result.allowed and repo_result.exit_code == 0:
                        env_info["package_manager"][manager]["repositories"] = repo_result.stdout
                elif manager == "yum":
                    repo_result = self.executor.execute("yum repolist")
                    if repo_result.allowed and repo_result.exit_code == 0:
                        env_info["package_manager"][manager]["repositories"] = repo_result.stdout
            else:
                env_info["package_manager"][manager] = {"available": False}
        
        # Available tools and commands
        common_tools = [
            "curl", "wget", "git", "vim", "nano", "htop", "tree", "unzip", "zip",
            "docker", "nginx", "apache2", "mysql", "python3", "pip", "node", "npm",
            "java", "gcc", "make", "systemctl", "service", "crontab", "iptables",
            "ufw", "firewall-cmd", "ss", "netstat", "rsync", "tar", "gzip"
        ]
        
        for tool in common_tools:
            result = self.executor.execute(f"which {tool} 2>/dev/null && {tool} --version 2>/dev/null | head -1")
            if result.allowed and result.exit_code == 0:
                env_info["available_tools"][tool] = {
                    "available": True,
                    "path": result.stdout.split('\n')[0] if result.stdout else "unknown",
                    "version": result.stdout.split('\n')[1] if len(result.stdout.split('\n')) > 1 else "unknown"
                }
            else:
                env_info["available_tools"][tool] = {"available": False}
        
        # System resources
        resource_commands = [
            ("memory", "free -h"),
            ("disk_space", "df -h"),
            ("cpu_info", "cat /proc/cpuinfo | grep 'model name' | head -1"),
            ("load_average", "uptime"),
            ("running_processes", "ps aux | wc -l")
        ]
        
        for key, cmd in resource_commands:
            result = self.executor.execute(cmd)
            if result.allowed and result.exit_code == 0:
                env_info["system_resources"][key] = result.stdout.strip()
        
        # Network information
        network_commands = [
            ("interfaces", "ip addr show | grep -E '^[0-9]+:' | head -5"),
            ("routing", "ip route | head -5"),
            ("dns", "cat /etc/resolv.conf | grep nameserver"),
            ("connectivity", "ping -c 1 8.8.8.8 2>/dev/null && echo 'internet_ok' || echo 'no_internet'")
        ]
        
        for key, cmd in network_commands:
            result = self.executor.execute(cmd)
            if result.allowed and result.exit_code == 0:
                env_info["network_info"][key] = result.stdout.strip()
        
        # User and permission context
        user_commands = [
            ("current_user", "whoami"),
            ("user_id", "id"),
            ("sudo_access", "sudo -n true 2>/dev/null && echo 'has_sudo' || echo 'no_sudo'"),
            ("home_directory", "echo $HOME"),
            ("current_directory", "pwd"),
            ("shell", "echo $SHELL")
        ]
        
        for key, cmd in user_commands:
            result = self.executor.execute(cmd)
            if result.allowed and result.exit_code == 0:
                env_info["user_context"][key] = result.stdout.strip()
        
        # Filesystem information
        fs_commands = [
            ("mount_points", "mount | head -10"),
            ("filesystem_types", "df -T"),
            ("disk_usage_summary", "du -sh /var /tmp /home 2>/dev/null | head -5")
        ]
        
        for key, cmd in fs_commands:
            result = self.executor.execute(cmd)
            if result.allowed and result.exit_code == 0:
                env_info["filesystem_info"][key] = result.stdout.strip()
        
        # Save to cache for future use
        self._save_environment_cache(env_info)
        
        return env_info
    
    def _should_invalidate_cache(self, task_description: str) -> bool:
        """Determine if a task might change system state and require cache invalidation"""
        system_changing_keywords = [
            "install", "remove", "uninstall", "update", "upgrade",
            "configure", "setup", "create user", "delete user",
            "start service", "stop service", "restart service",
            "enable service", "disable service", "mount", "unmount",
            "partition", "format", "network", "firewall", "iptables"
        ]

        task_lower = task_description.lower()
        return any(keyword in task_lower for keyword in system_changing_keywords)
    
    def execute_task(self, task_description: str, auto_approve: bool = False) -> TaskResult:
        """Break down complex tasks into commands using LLM with recursive failure recovery"""
        logger.info(f"Starting smart task execution: {task_description}")
        
        # Reset failure contexts for new task
        self.failure_contexts = []
        recovery_attempts = 0
        original_task = task_description
        
        # Check if we should invalidate cache for system-changing tasks
        if self._should_invalidate_cache(task_description):
            logger.info("Task may change system state, invalidating environment cache")
            self._invalidate_environment_cache()
        
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
        """Execute a single task attempt with comprehensive environment info"""
        # Collect comprehensive environment information
        logger.info("Collecting comprehensive environment information...")
        env_info = self._collect_comprehensive_environment_info()
        
        # Get current system state
        current_state = self.context.get_current_state()
        
        # Combine environment info with current state
        comprehensive_state = {
            "environment": env_info,
            "current_state": current_state,
            "task_description": task_description
        }
        
        # Get LLM action plan with full environment context
        action_plan = self.analyzer.suggest_actions(task_description, comprehensive_state)
        
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
        
        # Validate action plan safety with environment context
        validation = self.analyzer.validate_action_plan(commands, comprehensive_state)
        
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
        skipped_steps = []

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
                logger.warning(f"Step {i+1} failed with exit code {result.exit_code}")
                
                # Validate if we should continue despite failure
                validation = self._validate_step_completion(step, result, task_description)
                
                if validation.get("continue", False):
                    logger.info(f"Continuing despite failure: {validation.get('reason', 'Unknown reason')}")
                    
                    if validation.get("step_achieved", False):
                        completed_steps += 1
                        skipped_steps.append({
                            "step": i+1,
                            "description": description,
                            "reason": validation.get("reason", ""),
                            "skip_reason": validation.get("skip_reason", "")
                        })
                    
                    # Create new result with validation info
                    result = CommandResult(
                        stdout=result.stdout,
                        stderr=result.stderr,
                        exit_code=result.exit_code,
                        command=result.command,
                        allowed=result.allowed,
                        reason=result.reason,
                        validation_info=validation
                    )
                    results[-1] = result  # Replace the last result with the updated one
                    continue
                else:
                    logger.error(f"Critical failure at step {i+1}: {validation.get('reason', 'Unknown')}")
                    return TaskResult(
                        task_description=task_description,
                        success=False,
                        steps_completed=completed_steps,
                        total_steps=len(action_plan.steps),
                        results=results,
                        error_message=f"Critical failure: {validation.get('reason', result.stderr)}",
                        skipped_steps=skipped_steps
                    )
            else:
                completed_steps += 1

        # Create successful result with skipped steps info
        success_result = TaskResult(
            task_description=task_description,
            success=True,
            steps_completed=completed_steps,
            total_steps=len(action_plan.steps),
            results=results
        )

        # Add skipped steps information
        success_result.skipped_steps = skipped_steps

        return success_result
    
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
    
            def _should_invalidate_cache(self, task_description: str) -> bool:
                """Determine if a task might change system state and require cache invalidation"""
                system_changing_keywords = [
                    "install", "remove", "uninstall", "update", "upgrade",
                    "configure", "setup", "create user", "delete user",
                    "start service", "stop service", "restart service",
                    "enable service", "disable service", "mount", "unmount",
                    "partition", "format", "network", "firewall", "iptables"
                ]
        
                task_lower = task_description.lower()
                return any(keyword in task_lower for keyword in system_changing_keywords)
            
            return recovery_plan
            
        except Exception as e:
            logger.error(f"Failed to get recovery plan: {e}")
            return self._create_fallback_plan(original_task, failure_analysis)
    
    def _validate_step_completion(self, step: Dict[str, Any], result: CommandResult, 
                                original_goal: str) -> Dict[str, Any]:
        """Validate if a step should be considered successful even if command failed"""
        command = step.get("command", "") if isinstance(step, dict) else str(step)
        description = step.get("description", "") if isinstance(step, dict) else ""
        
        # If command succeeded, no need for validation
        if result.exit_code == 0:
            return {"continue": True, "reason": "Command succeeded", "step_achieved": True}
        
        # Check for common "already exists" scenarios
        already_exists_patterns = [
            ("user.*already exists", "user creation"),
            ("group.*already exists", "group creation"),
            ("file exists", "file creation"),
            ("directory.*exists", "directory creation"),
            ("package.*already.*installed", "package installation"),
            ("service.*already.*running", "service start"),
            ("service.*already.*enabled", "service enable"),
            ("already.*member", "group membership"),
            ("nothing to do", "package operation"),
            ("no change", "configuration change")
        ]
        
        stderr_lower = result.stderr.lower()
        stdout_lower = result.stdout.lower()
        
        for pattern, operation_type in already_exists_patterns:
            if pattern in stderr_lower or pattern in stdout_lower:
                logger.info(f"Step appears already completed: {operation_type}")
                return {
                    "continue": True, 
                    "reason": f"Step already completed: {operation_type}",
                    "step_achieved": True,
                    "skip_reason": f"Target already exists: {pattern}"
                }
        
        # For unclear failures, consult LLM
        return self._consult_llm_for_step_validation(step, result, original_goal)

    def _consult_llm_for_step_validation(self, step: Dict[str, Any], result: CommandResult, 
                                       original_goal: str) -> Dict[str, Any]:
        """Enhanced LLM consultation with comprehensive failure context"""
        
        # Create enhanced failure context
        enhanced_context = self._create_enhanced_failure_context(
            result, step, original_goal, [result]
        )
        
        # Use LLM analyzer for command analysis
        command_analysis = self.analyzer.analyze_command_for_missing_info(
            result.command,
            result.stderr,
            enhanced_context
        )
        
        prompt = f"""
        A command in an execution plan has failed. Analyze the failure and provide guidance.
        
        FAILURE ANALYSIS:
        =================
        Original Goal: {original_goal}
        Failed Step: {enhanced_context['step_description']}
        
        Command Details:
        - Command: {enhanced_context['failure_details']['command']}
        - Exit Code: {enhanced_context['failure_details']['exit_code']}
        - Error Output: {enhanced_context['failure_details']['stderr']}
        - Standard Output: {enhanced_context['failure_details']['stdout']}
        
        LLM Command Analysis:
        - Missing Info: {command_analysis.get('missing_info', [])}
        - Corrected Command: {command_analysis.get('corrected_command', '')}
        - Auto Generate: {command_analysis.get('auto_generate', [])}
        - Explanation: {command_analysis.get('explanation', '')}
        - Confidence: {command_analysis.get('confidence', 0.0)}
        
        Missing Information Analysis:
        - Missing Parameters: {enhanced_context['missing_info_analysis']['missing_parameters']}
        - Incomplete Command: {enhanced_context['missing_info_analysis']['incomplete_command']}
        - Requires Generation: {enhanced_context['missing_info_analysis']['requires_generation']}
        
        Previous Context:
        {json.dumps(enhanced_context['previous_context'], indent=2)}
        
        DECISION FRAMEWORK:
        ===================
        - If missing info can be auto-generated: CONTINUE with corrected command
        - If command syntax is wrong: CONTINUE with corrected command
        - If goal already achieved: CONTINUE and mark as achieved
        - If critical system error: STOP execution
        - If permission error: ANALYZE if alternative approach exists
        
        Respond in JSON format:
        {{
            "continue": true/false,
            "reason": "detailed explanation of decision",
            "step_achieved": true/false,
            "confidence": 0.8,
            "root_cause": "specific cause of failure",
            "corrected_command": "fixed command with placeholders",
            "auto_generate": ["list of items that can be auto-generated"],
            "alternative_approach": "different way to achieve the same goal",
            "verification_command": "command to verify if goal was achieved"
        }}
        """
        
        try:
            response = self.analyzer._call_llm(prompt)
            validation_result = json.loads(response)
            
            # Use the LLM analyzer's corrected command if validation doesn't provide one
            if not validation_result.get("corrected_command") and command_analysis.get("corrected_command"):
                validation_result["corrected_command"] = command_analysis["corrected_command"]
                validation_result["auto_generate"] = command_analysis.get("auto_generate", [])
            
            # If LLM suggests auto-generation, try to generate missing info
            auto_generate = validation_result.get("auto_generate", [])
            corrected_command = validation_result.get("corrected_command", "")
            
            if auto_generate and corrected_command:
                logger.info(f"Attempting to auto-generate: {auto_generate}")
                
                # Generate missing information
                generated_values = {}
                for item in auto_generate:
                    try:
                        generated_value = self._generate_missing_information(item, enhanced_context)
                        generated_values[item] = generated_value
                        logger.info(f"Generated {item}: {generated_value[:20]}...")
                    except Exception as e:
                        logger.error(f"Failed to generate {item}: {e}")
                        continue
                
                # Substitute generated values into corrected command
                if generated_values:
                    final_command = corrected_command
                    for item, value in generated_values.items():
                        # Replace various placeholder formats
                        placeholders = [f"<{item}>", f"{{{item}}}", f"<{item.upper()}>", f"{{{item.upper()}}}"]
                        for placeholder in placeholders:
                            final_command = final_command.replace(placeholder, value)
                    
                    validation_result["generated_command"] = final_command
                    validation_result["generated_values"] = generated_values
            
            # Try verification command if provided
            verification_cmd = validation_result.get("verification_command", "")
            if verification_cmd:
                verify_result = self.executor.execute(verification_cmd)
                validation_result["verification_result"] = {
                    "exit_code": verify_result.exit_code,
                    "stdout": verify_result.stdout,
                    "stderr": verify_result.stderr
                }
                
                # Adjust decision based on verification
                if verify_result.exit_code == 0:
                    validation_result["step_achieved"] = True
                    validation_result["continue"] = True
                    validation_result["reason"] += " (verified goal already achieved)"
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Enhanced LLM validation failed: {e}")
            return {
                "continue": False,
                "reason": f"LLM validation failed: {str(e)}",
                "step_achieved": False,
                "confidence": 0.0,
                "root_cause": "analysis_failed"
            }
    
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
    
    def _create_enhanced_failure_context(self, result: CommandResult, step: Dict[str, Any], 
                                       original_goal: str, previous_results: List[CommandResult]) -> Dict[str, Any]:
        """Create comprehensive failure context for LLM analysis"""
        command = step.get("command", "") if isinstance(step, dict) else str(step)
        description = step.get("description", "") if isinstance(step, dict) else ""
        
        # Analyze missing information patterns
        missing_info_analysis = {
            "missing_parameters": self._detect_missing_parameters(result.command, result.stderr),
            "incomplete_command": self._is_incomplete_command(result.command, result.stderr),
            "requires_generation": self._requires_auto_generation(result.command, result.stderr)
        }
        
        # Get previous context from earlier commands
        previous_context = {}
        for prev_result in previous_results[-5:]:  # Last 5 commands for context
            if prev_result.exit_code == 0:
                previous_context[prev_result.command] = {
                    "stdout": prev_result.stdout[:200],
                    "success": True
                }
        
        return {
            "step_description": description,
            "failure_details": {
                "command": result.command,
                "exit_code": result.exit_code,
                "stderr": result.stderr,
                "stdout": result.stdout
            },
            "missing_info_analysis": missing_info_analysis,
            "previous_context": previous_context,
            "original_goal": original_goal
        }
    
    def _detect_missing_parameters(self, command: str, stderr: str) -> List[str]:
        """Detect what parameters are missing from a command"""
        missing_params = []
        
        # Common patterns for missing parameters
        patterns = [
            ("password", ["password required", "password:", "enter password"]),
            ("username", ["username required", "user not specified"]),
            ("filename", ["file not specified", "no input file"]),
            ("port", ["port required", "no port specified"]),
            ("key", ["key required", "no key specified"])
        ]
        
        stderr_lower = stderr.lower()
        for param, error_patterns in patterns:
            if any(pattern in stderr_lower for pattern in error_patterns):
                missing_params.append(param)
        
        return missing_params
    
    def _is_incomplete_command(self, command: str, stderr: str) -> bool:
        """Check if command appears to be incomplete"""
        incomplete_indicators = [
            "incomplete command",
            "missing argument",
            "expected argument",
            "usage:",
            "try --help"
        ]
        
        return any(indicator in stderr.lower() for indicator in incomplete_indicators)
    
    def _requires_auto_generation(self, command: str, stderr: str) -> List[str]:
        """Determine what values need to be auto-generated"""
        generation_needed = []
        
        # Commands that commonly need generated values
        if "passwd" in command and "password" not in command:
            generation_needed.append("password")
        
        if "useradd" in command and "password" not in stderr.lower():
            generation_needed.append("password")
        
        if "openssl" in command and "genrsa" in command:
            generation_needed.append("secure_key")
        
        if "backup" in command.lower() and not any(char.isdigit() for char in command):
            generation_needed.append("timestamp")
        
        return generation_needed
    
    def _generate_missing_information(self, info_type: str, context: Dict[str, Any]) -> str:
        """Generate missing information based on type"""
        import secrets
        import string
        from datetime import datetime
        
        if info_type in ["password", "<password>", "{password}"]:
            # Generate secure password
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            return ''.join(secrets.choice(alphabet) for _ in range(16))
        
        elif info_type in ["random_string", "<random_string>", "{random_string}"]:
            # Generate random alphanumeric string
            return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        
        elif info_type in ["timestamp", "<timestamp>", "{timestamp}"]:
            # Generate timestamp
            return datetime.now().strftime("%Y%m%d_%H%M%S")
        
        elif info_type in ["temp_file", "<temp_file>", "{temp_file}"]:
            # Generate temporary filename
            random_suffix = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(8))
            return f"tmp_{random_suffix}"
        
        elif info_type in ["secure_key", "<secure_key>", "{secure_key}"]:
            # Generate secure key identifier
            return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        
        elif info_type in ["random_port", "<random_port>", "{random_port}"]:
            # Generate random port in safe range
            return str(secrets.randbelow(10000) + 50000)  # 50000-59999
        
        else:
            # Default to random string
            return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    
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
        """Create specific prompt for command not found errors with environment context"""
        missing_package = failure_analysis.get("missing_package", "unknown")
        
        # Extract environment info
        env_info = current_state.get("environment", {})
        distribution = env_info.get("distribution", {})
        package_managers = env_info.get("package_manager", {})
        available_tools = env_info.get("available_tools", {})
        
        # Determine the best package manager
        available_pm = []
        for pm, info in package_managers.items():
            if info.get("available", False):
                available_pm.append(pm)
        
        return f"""
        COMMAND NOT FOUND ERROR - Need Recovery Plan
        
        Original Task: {original_task}
        Failed Command: {failed_result.command}
        Error: {failed_result.stderr}
        Missing Command: {failed_result.command.split()[0]}
        
        LINUX ENVIRONMENT DETAILS:
        Distribution: {distribution.get('os_release', 'Unknown')}
        Kernel: {distribution.get('kernel', 'Unknown')}
        Architecture: {distribution.get('architecture', 'Unknown')}
        
        Available Package Managers: {available_pm}
        Package Manager Details:
        {json.dumps(package_managers, indent=2)}
        
        Available Tools:
        {json.dumps({k: v for k, v in available_tools.items() if v.get('available', False)}, indent=2)}
        
        User Context:
        {json.dumps(env_info.get('user_context', {}), indent=2)}
        
        System Resources:
        {json.dumps(env_info.get('system_resources', {}), indent=2)}
        
        Create a recovery plan that:
        1. Uses the CORRECT package manager for this distribution
        2. Installs the missing package ({missing_package}) using distribution-specific commands
        3. If the package name is wrong for this distribution, finds the correct package name
        4. If installation fails, finds alternative commands/packages available on this system
        5. If no alternatives work, revises the original task using available tools
        
        IMPORTANT DISTRIBUTION-SPECIFIC CONSIDERATIONS:
        - For Ubuntu/Debian: use apt/apt-get
        - For RHEL/CentOS/Fedora: use yum/dnf
        - For Arch: use pacman
        - For SUSE: use zypper
        - For Alpine: use apk
        
        Package name variations by distribution:
        - docker: docker.io (Ubuntu), docker-ce (RHEL), docker (Arch)
        - apache: apache2 (Debian), httpd (RHEL)
        - nginx: nginx (most), nginx-mainline (some)
        
        Example recovery steps for this environment:
        1. Update package lists: "{available_pm[0] if available_pm else 'apt'} update"
        2. Install package: "{available_pm[0] if available_pm else 'apt'} install -y {missing_package}"
        3. Verify installation: "which {failed_result.command.split()[0]}"
        4. If fails, try alternatives based on available tools
        
        Respond in JSON format with detailed, distribution-specific steps.
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
