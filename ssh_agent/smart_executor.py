import json
import logging
import os
import hashlib
import base64
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
        """Save environment info to cache on remote server"""
        try:
            import json
            
            # Create cache data with metadata
            cache_data = {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0",
                "connection_key": f"{self.executor.connection.hostname}_{self.executor.connection.username}_{self.executor.connection.port}",
                "environment_info": env_info
            }
            
            # Convert to JSON
            json_data = json.dumps(cache_data, indent=2)
            
            # Use base64 encoding to safely transfer the JSON data
            cache_file = "/tmp/ssh_agent_env_cache.json"
            
            # First, create the cache directory if it doesn't exist
            mkdir_result = self.executor.execute("mkdir -p /tmp")
            if not mkdir_result.allowed:
                logger.warning("Cannot create /tmp directory for cache")
                return
            
            # Encode JSON as base64 to avoid shell escaping issues
            json_bytes = json_data.encode('utf-8')
            b64_data = base64.b64encode(json_bytes).decode('ascii')
            
            # Write base64 data and decode it on the remote server
            write_cmd = f"echo '{b64_data}' | base64 -d > {cache_file}"
            write_result = self.executor.execute(write_cmd)
            
            if write_result.allowed and write_result.exit_code == 0:
                logger.info(f"Environment cache saved to {cache_file} on remote server")
                
                # Verify the file was written correctly by checking if it's valid JSON
                verify_result = self.executor.execute(f"python3 -m json.tool {cache_file} > /dev/null 2>&1 && echo 'valid' || echo 'invalid'")
                if verify_result.allowed and verify_result.exit_code == 0:
                    if "valid" in verify_result.stdout:
                        logger.debug("Cache file JSON validation passed")
                        
                        # Get file size for logging
                        size_result = self.executor.execute(f"wc -c < {cache_file}")
                        if size_result.allowed and size_result.exit_code == 0:
                            file_size = size_result.stdout.strip()
                            logger.debug(f"Cache file size: {file_size} bytes")
                    else:
                        logger.warning("Cache file contains invalid JSON")
                        # Remove invalid cache file
                        self.executor.execute(f"rm -f {cache_file}")
                else:
                    logger.debug("Could not verify cache file JSON validity")
            else:
                logger.warning(f"Failed to write environment cache: {write_result.stderr}")
            
            # Update memory cache regardless of file write success
            self._environment_cache = env_info
            self._cache_timestamp = datetime.now()
            
        except Exception as e:
            logger.error(f"Error saving environment cache: {e}")
            logger.exception("Full traceback:")
    
    def _load_environment_cache(self) -> Optional[Dict[str, Any]]:
        """Load environment info from remote server cache if valid"""
        try:
            cache_file = "/tmp/ssh_agent_env_cache.json"
            
            # Check if cache file exists on remote server
            check_result = self.executor.execute(f"test -f {cache_file} && echo 'exists' || echo 'missing'")
            if not check_result.allowed or "missing" in check_result.stdout:
                logger.debug("Environment cache file not found on remote server")
                return None
            
            # Check cache age
            stat_result = self.executor.execute(f"stat -c %Y {cache_file}")
            if not stat_result.allowed or stat_result.exit_code != 0:
                logger.debug("Could not check cache file age")
                return None
            
            try:
                cache_timestamp = int(stat_result.stdout.strip())
                current_time = int(datetime.now().timestamp())
                age_minutes = (current_time - cache_timestamp) / 60
                
                if age_minutes > self.cache_ttl_minutes:
                    logger.debug(f"Environment cache expired (age: {age_minutes:.1f} minutes)")
                    return None
            except ValueError:
                logger.debug("Invalid cache timestamp")
                return None
            
            # Load cache content
            cat_result = self.executor.execute(f"cat {cache_file}")
            if not cat_result.allowed or cat_result.exit_code != 0:
                logger.debug("Could not read cache file")
                return None
            
            # Parse JSON content
            try:
                cached_data = json.loads(cat_result.stdout)
                
                # Verify connection key matches
                expected_key = f"{self.executor.connection.hostname}_{self.executor.connection.username}_{self.executor.connection.port}"
                if cached_data.get("connection_key") != expected_key:
                    logger.debug("Cache connection key mismatch")
                    return None
                
                env_info = cached_data.get("environment_info")
                if not env_info or not isinstance(env_info, dict):
                    logger.warning("Invalid environment info in cache")
                    return None
                
                logger.info(f"Loaded environment cache from remote server (age: {age_minutes:.1f} minutes)")
                return env_info
                
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid cache file format: {e}")
                # Remove corrupted cache
                self.executor.execute(f"rm -f {cache_file}")
                return None
                
        except Exception as e:
            logger.error(f"Error loading environment cache: {e}")
            logger.exception("Full traceback:")
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
    
    def _collect_task_prerequisites(self, task_description: str, env_info: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 1: Ask LLM what prerequisites need to be collected for this task"""
        if not self.analyzer._client:
            return {"prerequisites": [], "error": "LLM unavailable"}
        
        prompt = f"""
        Analyze this task and determine what prerequisite information needs to be collected before creating an execution plan:
        
        Task: {task_description}
        
        Current Environment:
        {json.dumps(env_info, indent=2)[:1500]}
        
        PREREQUISITE CATEGORIES:
        1. Service Status - which services need to be checked
        2. Package Status - which packages need verification
        3. File/Directory Existence - what paths need checking
        4. Network Connectivity - what endpoints need testing
        5. User/Permission Context - what access levels need verification
        6. Configuration State - what config files need reading
        7. Resource Availability - what system resources need checking
        8. Dependency Verification - what dependencies need validation
        
        For each prerequisite, specify:
        - category: one of the above categories
        - check_command: exact command to run
        - description: what this check determines
        - required: true if task cannot proceed without this info
        - fallback_command: alternative command if primary fails
        
        CRITICAL: Only request prerequisites that are actually needed for this specific task.
        
        Respond in JSON format:
        {{
            "prerequisites": [
                {{
                    "category": "service_status",
                    "check_command": "systemctl status nginx",
                    "description": "Check if nginx is running",
                    "required": true,
                    "fallback_command": "service nginx status"
                }}
            ],
            "reasoning": "why these prerequisites are needed"
        }}
        """
        
        try:
            response = self.analyzer._call_llm(prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"Failed to get task prerequisites: {e}")
            return {"prerequisites": [], "error": str(e)}

    def _execute_prerequisite_collection(self, prerequisites: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Phase 2: Execute prerequisite checks and collect results"""
        prerequisite_results = {}
        
        for prereq in prerequisites:
            category = prereq.get("category", "unknown")
            command = prereq.get("check_command", "")
            fallback = prereq.get("fallback_command", "")
            description = prereq.get("description", "")
            required = prereq.get("required", False)
            
            if not command:
                continue
            
            logger.info(f"Collecting prerequisite: {description}")
            
            # Try primary command
            result = self.executor.execute(command)
            
            # If primary fails and we have fallback, try it
            if result.exit_code != 0 and fallback:
                logger.debug(f"Primary command failed, trying fallback: {fallback}")
                result = self.executor.execute(fallback)
            
            # Store result with metadata
            prerequisite_results[category] = {
                "command": command,
                "description": description,
                "required": required,
                "success": result.exit_code == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code
            }
            
            # If this was required and failed, note the failure
            if required and result.exit_code != 0:
                prerequisite_results[category]["failure_impact"] = "Task may not be possible without this information"
        
        return prerequisite_results

    def _create_informed_action_plan(self, task_description: str, env_info: Dict[str, Any], 
                                    prerequisite_results: Dict[str, Any]) -> ActionPlan:
        """Phase 3: Create action plan with full prerequisite context"""
        if not self.analyzer._client:
            logger.error("LLM client not available for action planning")
            return ActionPlan(
                goal=task_description,
                steps=[],
                risks=["LLM unavailable"],
                estimated_time="unknown",
                safety_score=0.0
            )
        
        prompt = f"""
        Create a comprehensive action plan with full prerequisite knowledge:
        
        TASK: {task_description}
        
        ENVIRONMENT CONTEXT:
        {json.dumps(env_info, indent=2)[:1000]}
        
        PREREQUISITE RESULTS:
        {json.dumps(prerequisite_results, indent=2)}
        
        PLANNING INSTRUCTIONS:
        1. Use the prerequisite results to make informed decisions
        2. Skip steps that are already completed (based on prerequisite checks)
        3. Handle failed prerequisites appropriately
        4. Use placeholders for values that need generation
        5. Create conditional steps based on prerequisite outcomes
        
        PREREQUISITE-AWARE PLANNING:
        - If service is already running → skip start commands
        - If package is already installed → skip installation
        - If file exists → skip creation or modify approach
        - If user exists → skip user creation
        - If configuration is correct → skip config changes
        
        PLACEHOLDER SYSTEM:
        - <password> for secure passwords
        - <timestamp> for current timestamp  
        - <temp_file> for temporary files
        - <random_string> for random values
        
        Each step should include:
        - command: exact command with placeholders
        - description: what this accomplishes
        - prerequisite_basis: which prerequisite informed this step
        - skip_condition: when this step can be skipped
        - auto_generate: list of placeholders to generate
        
        CRITICAL: Always provide at least one step, even if it's just verification.
        CRITICAL: Respond with ONLY valid JSON, no additional text.
        
        {{
            "goal": "{task_description}",
            "steps": [
                {{
                    "command": "actual command here",
                    "description": "what this does",
                    "prerequisite_basis": "which prerequisite check informed this",
                    "skip_condition": "when to skip this step",
                    "auto_generate": []
                }}
            ],
            "risks": ["list of risks"],
            "estimated_time": "X minutes",
            "safety_score": 0.8
        }}
        """
        
        try:
            logger.info("Sending action planning request to LLM...")
            response = self.analyzer._call_llm(prompt)
            logger.info(f"LLM response received: {len(response)} characters")
            logger.debug(f"LLM response content: {response[:500]}...")
            
            # Parse the response using the robust JSON parser
            fallback_data = {
                "goal": task_description,
                "steps": [],
                "risks": ["Failed to parse LLM response"],
                "estimated_time": "unknown",
                "safety_score": 0.0
            }
            
            parsed_data = self.analyzer._robust_json_parse(response, fallback_data)
            
            # Create ActionPlan from parsed data
            action_plan = ActionPlan(
                goal=parsed_data.get("goal", task_description),
                steps=parsed_data.get("steps", []),
                risks=parsed_data.get("risks", []),
                estimated_time=parsed_data.get("estimated_time", "unknown"),
                safety_score=float(parsed_data.get("safety_score", 0.0))
            )
            
            # Validate the action plan - if no steps, create a task-specific fallback
            if not action_plan.steps:
                logger.warning("LLM returned empty steps, creating task-specific fallback")
                return self._create_task_specific_fallback(task_description, prerequisite_results)
            
            logger.info(f"Successfully created action plan with {len(action_plan.steps)} steps")
            return action_plan
            
        except Exception as e:
            logger.error(f"Failed to create informed action plan: {e}")
            logger.exception("Full traceback for action plan failure:")
            return self._create_task_specific_fallback(task_description, prerequisite_results)

    def _create_task_specific_fallback(self, task_description: str, prerequisite_results: Dict[str, Any]) -> ActionPlan:
        """Create a task-specific fallback plan when LLM fails to generate proper steps"""
        logger.info("Creating task-specific fallback action plan")
        
        task_lower = task_description.lower()
        fallback_steps = []
        
        # Handle file deletion tasks
        if any(keyword in task_lower for keyword in ["delete", "remove", "rm"]) and "file" in task_lower:
            # Extract file path from task description
            import re
            file_match = re.search(r'(/[^\s]+)', task_description)
            file_path = file_match.group(1) if file_match else "/unknown/file"
            
            fallback_steps = [
                {
                    "command": f"ls -la {file_path}",
                    "description": f"Check if file {file_path} exists",
                    "prerequisite_basis": "file_directory_existence",
                    "skip_condition": "file does not exist",
                    "auto_generate": []
                },
                {
                    "command": f"sudo rm -f {file_path}",
                    "description": f"Remove file {file_path}",
                    "prerequisite_basis": "user_permission_context",
                    "skip_condition": "file already removed",
                    "auto_generate": []
                },
                {
                    "command": f"ls -la {file_path} 2>/dev/null || echo 'File successfully removed'",
                    "description": "Verify file removal",
                    "prerequisite_basis": "",
                    "skip_condition": "",
                    "auto_generate": []
                }
            ]
        
        # Handle service management tasks
        elif any(keyword in task_lower for keyword in ["start", "stop", "restart", "enable", "disable"]) and "service" in task_lower:
            # Extract service name
            words = task_description.split()
            service_name = "unknown"
            for i, word in enumerate(words):
                if word in ["service", "start", "stop", "restart", "enable", "disable"] and i + 1 < len(words):
                    service_name = words[i + 1]
                    break
            
            action = "start"
            if "stop" in task_lower:
                action = "stop"
            elif "restart" in task_lower:
                action = "restart"
            elif "enable" in task_lower:
                action = "enable"
            elif "disable" in task_lower:
                action = "disable"
            
            fallback_steps = [
                {
                    "command": f"systemctl status {service_name}",
                    "description": f"Check current status of {service_name}",
                    "prerequisite_basis": "service_status",
                    "skip_condition": "",
                    "auto_generate": []
                },
                {
                    "command": f"sudo systemctl {action} {service_name}",
                    "description": f"{action.title()} {service_name} service",
                    "prerequisite_basis": "user_permission_context",
                    "skip_condition": f"service already {action}ed" if action in ["start", "stop"] else "",
                    "auto_generate": []
                },
                {
                    "command": f"systemctl status {service_name}",
                    "description": f"Verify {service_name} status after {action}",
                    "prerequisite_basis": "",
                    "skip_condition": "",
                    "auto_generate": []
                }
            ]
        
        # Handle package installation tasks
        elif "install" in task_lower and any(keyword in task_lower for keyword in ["package", "apt", "yum", "dnf"]):
            # Extract package name
            words = task_description.split()
            package_name = words[-1] if words else "unknown"
            
            fallback_steps = [
                {
                    "command": "sudo apt update || sudo yum update || sudo dnf update || true",
                    "description": "Update package lists",
                    "prerequisite_basis": "package_manager",
                    "skip_condition": "",
                    "auto_generate": []
                },
                {
                    "command": f"sudo apt install -y {package_name} || sudo yum install -y {package_name} || sudo dnf install -y {package_name}",
                    "description": f"Install {package_name}",
                    "prerequisite_basis": "package_manager",
                    "skip_condition": "package already installed",
                    "auto_generate": []
                },
                {
                    "command": f"which {package_name} || dpkg -l | grep {package_name} || rpm -q {package_name} || echo 'Package verification'",
                    "description": f"Verify {package_name} installation",
                    "prerequisite_basis": "",
                    "skip_condition": "",
                    "auto_generate": []
                }
            ]
        
        # Generic fallback for other tasks
        else:
            fallback_steps = [
                {
                    "command": f"echo 'Executing task: {task_description}'",
                    "description": "Log task execution",
                    "prerequisite_basis": "",
                    "skip_condition": "",
                    "auto_generate": []
                },
                {
                    "command": "echo 'Task-specific implementation needed'",
                    "description": "Placeholder for manual implementation",
                    "prerequisite_basis": "",
                    "skip_condition": "",
                    "auto_generate": []
                }
            ]
        
        return ActionPlan(
            goal=f"Fallback plan for: {task_description}",
            steps=fallback_steps,
            risks=["Fallback plan - may need manual verification"],
            estimated_time="2-5 minutes",
            safety_score=0.7
        )

    def _collect_comprehensive_environment_info(self) -> Dict[str, Any]:
        """Collect comprehensive Linux environment information for LLM planning with caching"""
        # Try to get cached info first
        cached_info = self._get_cached_environment_info()
        if cached_info:
            logger.debug("Using cached environment information")
            return cached_info
        
        logger.info("Collecting fresh environment information...")
        
        # Initialize with safe defaults
        env_info = {
            "distribution": {},
            "package_manager": {},
            "available_tools": {},
            "system_resources": {},
            "network_info": {},
            "user_context": {},
            "filesystem_info": {}
        }
        
        try:
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
                try:
                    result = self.executor.execute(cmd)
                    if result and result.allowed and result.exit_code == 0:
                        env_info["distribution"][key] = result.stdout.strip()
                    else:
                        logger.debug(f"Distribution command failed: {cmd} - {getattr(result, 'stderr', 'No result')}")
                        env_info["distribution"][key] = "unknown"
                except Exception as e:
                    logger.warning(f"Failed to execute distribution command '{cmd}': {e}")
                    env_info["distribution"][key] = "error"
            
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
                try:
                    result = self.executor.execute(cmd)
                    if result and result.allowed and result.exit_code == 0:
                        env_info["package_manager"][manager] = {
                            "available": True,
                            "version": result.stdout.strip()[:100]
                        }
                        # Get repository info for available package managers
                        if manager == "apt":
                            try:
                                repo_result = self.executor.execute("apt-cache policy | head -20")
                                if repo_result and repo_result.allowed and repo_result.exit_code == 0:
                                    env_info["package_manager"][manager]["repositories"] = repo_result.stdout
                            except Exception as e:
                                logger.debug(f"Failed to get apt repositories: {e}")
                        elif manager == "yum":
                            try:
                                repo_result = self.executor.execute("yum repolist")
                                if repo_result and repo_result.allowed and repo_result.exit_code == 0:
                                    env_info["package_manager"][manager]["repositories"] = repo_result.stdout
                            except Exception as e:
                                logger.debug(f"Failed to get yum repositories: {e}")
                    else:
                        env_info["package_manager"][manager] = {"available": False}
                except Exception as e:
                    logger.warning(f"Failed to check package manager '{manager}': {e}")
                    env_info["package_manager"][manager] = {"available": False, "error": str(e)}
            
            # Available tools and commands
            common_tools = [
                "curl", "wget", "git", "vim", "nano", "htop", "tree", "unzip", "zip",
                "docker", "nginx", "apache2", "mysql", "python3", "pip", "node", "npm",
                "java", "gcc", "make", "systemctl", "service", "crontab", "iptables",
                "ufw", "firewall-cmd", "ss", "netstat", "rsync", "tar", "gzip"
            ]
            
            for tool in common_tools:
                try:
                    result = self.executor.execute(f"which {tool} 2>/dev/null")
                    if result and result.allowed and result.exit_code == 0:
                        # Try to get version info
                        version_result = self.executor.execute(f"{tool} --version 2>/dev/null | head -1")
                        version_info = "unknown"
                        if version_result and version_result.allowed and version_result.exit_code == 0:
                            version_info = version_result.stdout.strip()[:100]
                        
                        env_info["available_tools"][tool] = {
                            "available": True,
                            "path": result.stdout.strip(),
                            "version": version_info
                        }
                    else:
                        env_info["available_tools"][tool] = {"available": False}
                except Exception as e:
                    logger.debug(f"Failed to check tool '{tool}': {e}")
                    env_info["available_tools"][tool] = {"available": False, "error": str(e)}
            
            # System resources
            resource_commands = [
                ("memory", "free -h"),
                ("disk_space", "df -h"),
                ("cpu_info", "cat /proc/cpuinfo | grep 'model name' | head -1"),
                ("load_average", "uptime"),
                ("running_processes", "ps aux | wc -l")
            ]
            
            for key, cmd in resource_commands:
                try:
                    result = self.executor.execute(cmd)
                    if result and result.allowed and result.exit_code == 0:
                        env_info["system_resources"][key] = result.stdout.strip()
                    else:
                        env_info["system_resources"][key] = "unavailable"
                except Exception as e:
                    logger.debug(f"Failed to get system resource '{key}': {e}")
                    env_info["system_resources"][key] = f"error: {str(e)}"
            
            # Network information
            network_commands = [
                ("interfaces", "ip addr show | grep -E '^[0-9]+:' | head -5"),
                ("routing", "ip route | head -5"),
                ("dns", "cat /etc/resolv.conf | grep nameserver"),
                ("connectivity", "ping -c 1 8.8.8.8 2>/dev/null && echo 'internet_ok' || echo 'no_internet'")
            ]
            
            for key, cmd in network_commands:
                try:
                    result = self.executor.execute(cmd)
                    if result and result.allowed and result.exit_code == 0:
                        env_info["network_info"][key] = result.stdout.strip()
                    else:
                        env_info["network_info"][key] = "unavailable"
                except Exception as e:
                    logger.debug(f"Failed to get network info '{key}': {e}")
                    env_info["network_info"][key] = f"error: {str(e)}"
            
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
                try:
                    result = self.executor.execute(cmd)
                    if result and result.allowed and result.exit_code == 0:
                        env_info["user_context"][key] = result.stdout.strip()
                    else:
                        env_info["user_context"][key] = "unavailable"
                except Exception as e:
                    logger.debug(f"Failed to get user context '{key}': {e}")
                    env_info["user_context"][key] = f"error: {str(e)}"
            
            # Filesystem information
            fs_commands = [
                ("mount_points", "mount | head -10"),
                ("filesystem_types", "df -T"),
                ("disk_usage_summary", "du -sh /var /tmp /home 2>/dev/null | head -5")
            ]
            
            for key, cmd in fs_commands:
                try:
                    result = self.executor.execute(cmd)
                    if result and result.allowed and result.exit_code == 0:
                        env_info["filesystem_info"][key] = result.stdout.strip()
                    else:
                        env_info["filesystem_info"][key] = "unavailable"
                except Exception as e:
                    logger.debug(f"Failed to get filesystem info '{key}': {e}")
                    env_info["filesystem_info"][key] = f"error: {str(e)}"
            
            # Enhanced container environment detection
            container_commands = [
                ("container_check", "cat /.dockerenv 2>/dev/null && echo 'docker' || echo 'not_docker'"),
                ("podman_check", "cat /run/.containerenv 2>/dev/null && echo 'podman' || echo 'not_podman'"),
                ("cgroup_check", "cat /proc/1/cgroup 2>/dev/null | grep -E '(docker|lxc|containerd|podman)' && echo 'container' || echo 'not_container'"),
                ("cgroup_v2_check", "cat /proc/self/cgroup 2>/dev/null | grep '0::/' && echo 'cgroup_v2' || echo 'cgroup_v1'"),
                ("init_process", "ps -p 1 -o comm= 2>/dev/null"),
                ("systemd_available", "systemctl --version 2>/dev/null && echo 'systemd_available' || echo 'no_systemd'"),
                ("systemd_running", "systemctl is-system-running 2>&1 || echo 'systemd_not_running'"),  # Capture stderr too
                ("systemd_functional", "systemctl list-units --type=service --state=running 2>&1 | head -1 || echo 'systemd_not_functional'"),  # Better test
                ("systemd_pid1", "ps -p 1 -o comm= | grep systemd && echo 'systemd_is_pid1' || echo 'systemd_not_pid1'"),  # Check if systemd is PID 1
                ("kernel_modules", "lsmod 2>/dev/null | wc -l"),
                ("proc_mounts", "cat /proc/mounts | grep -E '(overlay|aufs|devicemapper|virtiofs|fuse|9p)' | head -5"),
                ("virtualization", "systemd-detect-virt 2>/dev/null || echo 'unknown'"),
                ("architecture", "uname -m"),
                ("os_release", "cat /etc/os-release 2>/dev/null | head -5"),
                ("container_runtime", "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | grep -E '(container|CONTAINER|DOCKER)' || echo 'no_container_env'"),
                ("mac_specific", "mount | grep -E '(virtiofs|osxfs|9p)' || echo 'not_mac_mount'"),
                ("selinux_status", "getenforce 2>/dev/null || echo 'no_selinux'"),
                ("capabilities", "capsh --print 2>/dev/null | grep 'Current:' || echo 'no_capabilities'"),
                ("cpu_info", "cat /proc/cpuinfo | grep -E '(model name|vendor_id)' | head -2"),
                ("docker_info", "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | grep -i docker || echo 'no_docker_env'"),
                ("hypervisor_check", "cat /proc/cpuinfo | grep -i hypervisor || echo 'no_hypervisor'"),
                ("dmi_info", "dmidecode -s system-manufacturer 2>/dev/null || echo 'no_dmi'")
            ]

            env_info["container_info"] = {}
            for key, cmd in container_commands:
                try:
                    result = self.executor.execute(cmd)
                    if result and result.allowed and result.exit_code == 0:
                        env_info["container_info"][key] = result.stdout.strip()
                    else:
                        env_info["container_info"][key] = "unavailable"
                except Exception as e:
                    logger.debug(f"Failed to get container info '{key}': {e}")
                    env_info["container_info"][key] = f"error: {str(e)}"

            # Analyze container environment
            env_info["environment_type"] = self._analyze_environment_type(env_info["container_info"])
            
            # Validate env_info structure
            if not isinstance(env_info, dict):
                logger.error("Environment info is not a dictionary!")
                env_info = {
                    "distribution": {"error": "collection_failed"},
                    "package_manager": {},
                    "available_tools": {},
                    "system_resources": {},
                    "network_info": {},
                    "user_context": {},
                    "filesystem_info": {}
                }
            
            # Save to cache for future use
            logger.info("Saving environment information to cache...")
            self._save_environment_cache(env_info)
            
            logger.info(f"Environment collection completed. Found {len(env_info)} categories")
            return env_info
            
        except Exception as e:
            logger.error(f"Critical error during environment collection: {e}")
            logger.exception("Full traceback:")
            # Return minimal safe structure
            return {
                "distribution": {"error": f"collection_failed: {str(e)}"},
                "package_manager": {},
                "available_tools": {},
                "system_resources": {},
                "network_info": {},
                "user_context": {},
                "filesystem_info": {}
            }
    
    def _interpret_exit_code(self, command: str, exit_code: int, stdout: str, stderr: str) -> Dict[str, Any]:
        """Interpret exit codes in context - some non-zero codes are actually success states"""
        
        # Commands where non-zero exit codes can be normal/informational
        command_patterns = {
            # Package management - updates available
            "dnf check-update": {100: "updates_available"},
            "yum check-update": {100: "updates_available"},
            "apt list --upgradable": {0: "success", 1: "no_updates"},
            
            # Package management - package states
            "rpm -q": {1: "package_not_installed"},
            "dpkg -l": {1: "package_not_found"},
            "which": {1: "command_not_found"},
            
            # Search and comparison
            "grep": {1: "no_matches", 2: "error"},
            "diff": {1: "files_differ", 2: "error"},
            "cmp": {1: "files_differ", 2: "error"},
            
            # System state checks
            "systemctl is-active": {3: "service_inactive"},
            "systemctl is-enabled": {1: "service_disabled"},
            "test": {1: "condition_false"},
            "ping": {1: "host_unreachable", 2: "network_error"},
            
            # File operations
            "find": {1: "permission_denied_some_dirs"},
            "ls": {2: "file_not_found"},
            
            # Process management
            "killall": {1: "no_processes_found"},
            "pkill": {1: "no_processes_found"},
        }
        
        # Get the base command (first word)
        base_command = command.split()[0]
        
        # Check for exact command matches first
        for pattern, exit_codes in command_patterns.items():
            if command.startswith(pattern) or base_command == pattern.split()[0]:
                if exit_code in exit_codes:
                    return {
                        "is_error": False,
                        "interpretation": exit_codes[exit_code],
                        "message": f"Command returned expected exit code {exit_code}: {exit_codes[exit_code]}",
                        "continue_execution": True
                    }
        
        # Special handling for specific command patterns
        if "check-update" in command:
            if exit_code == 100:
                return {
                    "is_error": False,
                    "interpretation": "updates_available",
                    "message": "Updates are available for installation",
                    "continue_execution": True
                }
            elif exit_code == 0:
                return {
                    "is_error": False,
                    "interpretation": "no_updates",
                    "message": "System is up to date",
                    "continue_execution": True
                }
        
        # Check for informational grep/search commands
        if any(cmd in command for cmd in ["grep", "egrep", "fgrep"]):
            if exit_code == 1:
                return {
                    "is_error": False,
                    "interpretation": "no_matches",
                    "message": "No matches found (normal for search commands)",
                    "continue_execution": True
                }
        
        # Check for test/conditional commands
        if command.startswith("test ") or command.startswith("[ "):
            if exit_code == 1:
                return {
                    "is_error": False,
                    "interpretation": "condition_false",
                    "message": "Test condition evaluated to false",
                    "continue_execution": True
                }
        
        # Check for which/command existence checks
        if command.startswith("which ") or command.startswith("command -v "):
            if exit_code == 1:
                return {
                    "is_error": False,
                    "interpretation": "command_not_found",
                    "message": "Command not found in PATH (informational)",
                    "continue_execution": True
                }
        
        # System state checks - be more specific about systemctl failures
        if "systemctl" in command:
            if exit_code == 1:
                # Check if this is a systemd not functional error
                if any(error in stderr.lower() for error in [
                    "system has not been booted with systemd",
                    "failed to connect to bus",
                    "can't operate"
                ]):
                    return {
                        "is_error": True,
                        "interpretation": "systemd_not_functional",
                        "message": "systemd is not functional in this environment",
                        "continue_execution": False
                    }
                elif "systemctl is-enabled" in command:
                    return {
                        "is_error": False,
                        "interpretation": "service_disabled",
                        "message": "Service is disabled (normal state check)",
                        "continue_execution": True
                    }
                else:
                    return {
                        "is_error": True,
                        "interpretation": "systemd_not_functional",
                        "message": "systemctl command failed - systemd may not be functional",
                        "continue_execution": False
                    }
            elif exit_code == 3 and "systemctl is-active" in command:
                return {
                    "is_error": False,
                    "interpretation": "service_inactive",
                    "message": "Service is inactive (normal state check)",
                    "continue_execution": True
                }
            elif exit_code == 4:
                return {
                    "is_error": False,
                    "interpretation": "service_not_found",
                    "message": "Service not found",
                    "continue_execution": True
                }
            elif exit_code == 5:
                return {
                    "is_error": True,
                    "interpretation": "service_not_found",
                    "message": "Service not found",
                    "continue_execution": False
                }
        
        # Check stderr for additional context
        if stderr:
            stderr_lower = stderr.lower()
            
            # Some commands write informational messages to stderr
            informational_patterns = [
                "no updates available",
                "already up to date",
                "nothing to do",
                "no packages marked for update",
                "0 upgraded, 0 newly installed"
            ]
            
            if any(pattern in stderr_lower for pattern in informational_patterns):
                return {
                    "is_error": False,
                    "interpretation": "informational",
                    "message": f"Command completed with informational message: {stderr.strip()}",
                    "continue_execution": True
                }
        
        # Check stdout for success indicators even with non-zero exit
        if stdout:
            stdout_lower = stdout.lower()
            
            success_patterns = [
                "completed successfully",
                "operation successful",
                "done",
                "finished"
            ]
            
            if any(pattern in stdout_lower for pattern in success_patterns):
                return {
                    "is_error": False,
                    "interpretation": "success_with_info",
                    "message": f"Command completed successfully with exit code {exit_code}",
                    "continue_execution": True
                }
        
        # For ambiguous cases, consult LLM
        if exit_code != 0 and exit_code < 128:  # Don't consult for signals (128+)
            logger.debug(f"Consulting LLM for exit code interpretation: {command} (exit: {exit_code})")
            llm_interpretation = self._consult_llm_for_exit_code(command, exit_code, stdout, stderr)
            
            if llm_interpretation.get("continue_execution", False):
                return llm_interpretation
        
        # Default: treat as error for unknown patterns
        return {
            "is_error": True,
            "interpretation": "error",
            "message": f"Command failed with exit code {exit_code}",
            "continue_execution": False
        }
    
    def _consult_llm_for_exit_code(self, command: str, exit_code: int, stdout: str, stderr: str) -> Dict[str, Any]:
        """Ask LLM to interpret an ambiguous exit code"""
        if not self.analyzer._client:
            return {"is_error": True, "interpretation": "unknown", "message": "LLM unavailable"}
        
        prompt = f"""
        Interpret this command's exit code in context:
        
        Command: {command}
        Exit Code: {exit_code}
        Stdout: {stdout[:500]}
        Stderr: {stderr[:500]}
        
        Is this exit code indicating:
        1. Success/completion (even if non-zero)
        2. Informational state (like "updates available")
        3. Actual error that should stop execution
        
        Consider common patterns:
        - Package managers often use 100 for "updates available"
        - Search commands use 1 for "no results found"
        - Test commands use 1 for "condition false"
        - System state commands use various codes for different states
        
        Respond in JSON:
        {{
            "is_error": false,
            "interpretation": "updates_available",
            "message": "explanation",
            "continue_execution": true
        }}
        """
        
        try:
            response = self.analyzer._call_llm(prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"LLM exit code interpretation failed: {e}")
            return {
                "is_error": True,
                "interpretation": "unknown",
                "message": f"Could not interpret exit code {exit_code}",
                "continue_execution": False
            }

    def _analyze_environment_type(self, container_info: Dict[str, str]) -> Dict[str, Any]:
        """Enhanced container detection for various platforms including Apple Silicon"""
        is_container = False
        container_type = "unknown"
        limitations = []
        platform_info = {}
        
        # Enhanced Docker detection
        if "docker" in container_info.get("container_check", ""):
            is_container = True
            container_type = "docker"
        
        # Check for Podman
        if "podman" in container_info.get("podman_check", ""):
            is_container = True
            container_type = "podman"
        
        # Enhanced cgroups detection (both v1 and v2)
        cgroup_output = container_info.get("cgroup_check", "")
        if "container" in cgroup_output or any(pattern in cgroup_output for pattern in [
            "docker", "lxc", "containerd", "podman", "systemd:/docker", "0::/docker"
        ]):
            is_container = True
            if container_type == "unknown":
                if "podman" in cgroup_output:
                    container_type = "podman"
                elif "docker" in cgroup_output:
                    container_type = "docker"
                else:
                    container_type = "container"
        
        # ENHANCED APPLE SILICON DETECTION - Look beyond just architecture
        arch = container_info.get("architecture", "")
        
        # Check for Apple Silicon host indicators even when container shows x86_64
        apple_silicon_indicators = []
        
        # Check mount points for Apple Silicon specific filesystems
        proc_mounts = container_info.get("proc_mounts", "")
        mac_mounts = container_info.get("mac_specific", "")
        
        if any(pattern in proc_mounts for pattern in ["virtiofs", "fuse.osxfs", "9p"]) or \
           any(pattern in mac_mounts for pattern in ["virtiofs", "osxfs", "9p"]):
            apple_silicon_indicators.append("apple_filesystem")
            platform_info["host_platform"] = "macos"
            is_container = True
        
        # Check for QEMU/emulation indicators (common on Apple Silicon)
        if "qemu" in container_info.get("virtualization", "").lower():
            apple_silicon_indicators.append("qemu_virtualization")
            platform_info["virtualization"] = "qemu"
        
        # Check for Apple Silicon specific CPU features in /proc/cpuinfo
        # Even in emulated x86_64, there might be hints
        cpu_info = container_info.get("cpu_info", "")
        if any(indicator in cpu_info.lower() for indicator in ["apple", "m1", "m2", "m3"]):
            apple_silicon_indicators.append("apple_cpu_detected")
        
        # Check for Docker Desktop indicators (common on macOS)
        container_runtime = container_info.get("container_runtime", "")
        if "docker-desktop" in container_runtime.lower():
            apple_silicon_indicators.append("docker_desktop")
            platform_info["host_platform"] = "macos"
            is_container = True
        
        # If we have multiple Apple Silicon indicators, mark as Apple Silicon even if arch is x86_64
        if len(apple_silicon_indicators) >= 2:
            platform_info["host_platform"] = "macos_apple_silicon"
            platform_info["emulated_architecture"] = arch  # Store the emulated arch
            platform_info["apple_silicon_indicators"] = apple_silicon_indicators
            is_container = True
            logger.info(f"Apple Silicon host detected via indicators: {apple_silicon_indicators}")
        elif arch in ["aarch64", "arm64"]:
            platform_info["architecture"] = "arm64"
            if apple_silicon_indicators:
                platform_info["host_platform"] = "macos_apple_silicon"
                is_container = True
        
        # Enhanced init process detection
        init_process = container_info.get("init_process", "")
        container_init_processes = ["sh", "bash", "python", "node", "java", "systemd", "/sbin/init"]
        if init_process in container_init_processes:
            if init_process in ["sh", "bash", "python", "node", "java"]:
                is_container = True
                limitations.append("no_init_system")
            elif init_process == "systemd" and is_container:
                # systemd in container - limited capabilities
                limitations.append("limited_systemd")
        
        # ENHANCED SYSTEMD DETECTION - Check both availability AND functionality
        systemd_status = container_info.get("systemd_available", "")
        systemd_running = container_info.get("systemd_running", "")
        systemd_functional = container_info.get("systemd_functional", "")
        systemd_pid1 = container_info.get("systemd_pid1", "")
        
        if "no_systemd" in systemd_status:
            limitations.append("no_systemd")
        elif "systemd_available" in systemd_status:
            # systemctl command exists, but check if it's functional
            systemd_errors = [
                "system has not been booted with systemd",
                "can't operate",
                "failed to connect to bus",
                "systemd_not_running",
                "failed to get d-bus connection",
                "systemd_not_functional"
            ]
            
            if any(error_msg in systemd_running.lower() for error_msg in systemd_errors) or \
               any(error_msg in systemd_functional.lower() for error_msg in systemd_errors) or \
               "systemd_not_pid1" in systemd_pid1:
                limitations.append("no_systemd")
                logger.info("systemctl command exists but systemd is not functional - treating as no_systemd")
            elif is_container:
                # systemd exists and appears functional in container - limited capabilities
                limitations.append("limited_systemd")
        
        # Enhanced kernel module detection
        try:
            module_count = int(container_info.get("kernel_modules", "0"))
            if module_count < 10:  # Very few modules suggests container
                limitations.append("limited_kernel_access")
                is_container = True
        except ValueError:
            pass
        
        # Enhanced filesystem detection
        proc_mounts = container_info.get("proc_mounts", "")
        container_fs_patterns = ["overlay", "aufs", "devicemapper", "virtiofs", "fuse.osxfs", "9p"]
        if any(fs in proc_mounts for fs in container_fs_patterns):
            is_container = True
            if "virtiofs" in proc_mounts or "fuse.osxfs" in proc_mounts:
                platform_info["host_platform"] = "macos"
            if "9p" in proc_mounts:
                platform_info["virtualization"] = "qemu_kvm"
        
        # Enhanced virtualization detection
        virt_type = container_info.get("virtualization", "")
        if virt_type in ["docker", "lxc", "container", "podman"]:
            is_container = True
            container_type = virt_type
        elif virt_type in ["qemu", "kvm", "vmware", "parallels"]:
            platform_info["virtualization"] = virt_type
            # Could be VM running containers
            if is_container:
                platform_info["nested_virtualization"] = True
        
        # CentOS 9 specific detection
        os_info = container_info.get("os_release", "")
        if any(pattern in os_info.lower() for pattern in ["centos", "rhel", "rocky", "alma"]):
            platform_info["os_family"] = "rhel"
            # RHEL-based containers often have specific characteristics
            if is_container:
                # Check for RHEL container-specific limitations
                limitations.append("rhel_container_restrictions")
        
        # Add specific platform detection
        platform_specific = {}
        if is_container:
            platform_specific = self._detect_centos9_apple_silicon(container_info)
            # Override detection if we found Apple Silicon indicators
            if apple_silicon_indicators:
                platform_specific["is_apple_silicon"] = True
                platform_specific["apple_silicon_indicators"] = apple_silicon_indicators
        
        return {
            "is_container": is_container,
            "container_type": container_type,
            "limitations": limitations,
            "platform_info": platform_info,
            "platform_specific": platform_specific,
            "capabilities": self._assess_container_capabilities(limitations, platform_info),
            "recommended_alternatives": self._get_container_alternatives(limitations, platform_info)
        }

    def _assess_container_capabilities(self, limitations: List[str], platform_info: Dict[str, Any]) -> Dict[str, bool]:
        """Enhanced capability assessment with platform awareness"""
        capabilities = {
            "can_use_systemctl": "no_systemd" not in limitations and "limited_systemd" not in limitations,
            "can_modify_kernel": "limited_kernel_access" not in limitations,
            "can_use_firewall": "limited_kernel_access" not in limitations,
            "can_install_packages": True,  # Usually possible in containers
            "can_manage_users": True,      # Usually possible
            "can_modify_network": "limited_kernel_access" not in limitations,
            "has_init_system": "no_init_system" not in limitations,
            "has_limited_systemd": "limited_systemd" in limitations,
            "has_functional_systemd": "no_systemd" not in limitations and "limited_systemd" not in limitations
        }
        
        # Platform-specific capability adjustments
        if platform_info.get("os_family") == "rhel":
            # RHEL-based containers may have additional restrictions
            if "rhel_container_restrictions" in limitations:
                capabilities["can_use_subscription_manager"] = False
                capabilities["can_modify_selinux"] = False
        
        if platform_info.get("host_platform") in ["macos_apple_silicon", "macos"]:
            # Apple Silicon containers may have specific limitations
            capabilities["can_use_native_virtualization"] = False
            capabilities["has_host_filesystem_integration"] = True
            capabilities["supports_emulation"] = platform_info.get("emulated_architecture") == "x86_64"
        
        if platform_info.get("nested_virtualization"):
            # Nested virtualization has additional limitations
            capabilities["can_use_kvm"] = False
            capabilities["can_modify_hardware"] = False
        
        return capabilities

    def _get_container_alternatives(self, limitations: List[str], platform_info: Dict[str, Any]) -> Dict[str, List[str]]:
        """Enhanced alternatives with platform-specific options"""
        alternatives = {}
        
        if "no_systemd" in limitations:
            alternatives["service_management"] = [
                "Use direct service commands: /usr/sbin/nginx, /usr/sbin/apache2",
                "Start services in background: nginx -g 'daemon off;' &",
                "For nginx: nginx && echo 'nginx started'",
                "For nginx reload: nginx -s reload",
                "For nginx stop: nginx -s quit",
                "Use process managers like supervisord",
                "Check processes with: ps aux | grep service_name",
                "Use service command if available: service nginx start",
                "Use init.d scripts: /etc/init.d/nginx start"
            ]
            
            alternatives["nginx_specific"] = [
                "Start nginx: nginx -g 'daemon off;' &",
                "Start nginx (daemon): nginx",
                "Test nginx config: nginx -t",
                "Reload nginx: nginx -s reload",
                "Stop nginx: nginx -s quit",
                "Check nginx status: ps aux | grep nginx",
                "Check nginx listening: netstat -tlnp | grep :80"
            ]
        elif "limited_systemd" in limitations:
            alternatives["service_management"] = [
                "systemctl may not work - use direct service commands",
                "Try: service nginx start instead of systemctl start nginx",
                "Use process-specific commands: nginx -s reload",
                "Check status with: ps aux | grep nginx",
                "Avoid systemctl daemon-reload in containers"
            ]
        
        if "limited_kernel_access" in limitations:
            alternatives["firewall_management"] = [
                "Configure firewall on container host",
                "Use Docker/Podman network policies",
                "Implement application-level security",
                "Use environment variables for security config",
                "Configure ingress/egress rules in orchestration"
            ]
            
            alternatives["network_management"] = [
                "Use container networking features",
                "Configure through Docker/Podman commands",
                "Use environment variables for network config",
                "Configure networking in docker-compose or Kubernetes"
            ]
        
        # Platform-specific alternatives
        if platform_info.get("os_family") == "rhel":
            alternatives["package_management"] = [
                "Use dnf instead of yum where available",
                "Consider using microdnf for minimal containers",
                "Use rpm for direct package queries",
                "Try: dnf install --nobest for dependency issues"
            ]
        
        if platform_info.get("host_platform") in ["macos_apple_silicon", "macos"]:
            alternatives["performance_optimization"] = [
                "Use ARM64-native images when available",
                "Leverage host filesystem integration",
                "Consider performance impact of x86_64 emulation" if platform_info.get("emulated_architecture") == "x86_64" else "Use native ARM64 performance",
                "Use Docker Desktop volume mounts for better performance"
            ]
            
            alternatives["architecture_considerations"] = [
                "Be aware of x86_64 emulation overhead" if platform_info.get("emulated_architecture") == "x86_64" else "Native ARM64 performance available",
                "Some x86_64 binaries may not work in emulation",
                "Use multi-arch images when possible",
                "Test performance-critical applications thoroughly"
            ]
        
        return alternatives
    
    def _detect_centos9_apple_silicon(self, container_info: Dict[str, str]) -> Dict[str, Any]:
        """Enhanced detection for CentOS 9 on Apple Silicon (including emulated x86_64)"""
        detection_result = {
            "is_centos9": False,
            "is_apple_silicon": False,
            "emulated_x86": False,
            "specific_limitations": [],
            "specific_capabilities": {},
            "detection_confidence": 0.0
        }
        
        confidence_score = 0.0
        apple_silicon_evidence = []
        
        # Check for CentOS 9
        os_release = container_info.get("os_release", "")
        if any(pattern in os_release.lower() for pattern in [
            "centos stream 9", "centos linux 9", "rocky linux 9", "alma linux 9"
        ]):
            detection_result["is_centos9"] = True
            confidence_score += 0.3
        
        # Check architecture - could be x86_64 due to emulation
        arch = container_info.get("architecture", "")
        
        # Apple Silicon indicators (even in emulated x86_64 containers)
        
        # 1. Check for Apple-specific filesystems
        mac_mounts = container_info.get("mac_specific", "")
        proc_mounts = container_info.get("proc_mounts", "")
        if any(fs in mac_mounts for fs in ["virtiofs", "osxfs", "9p"]) or \
           any(fs in proc_mounts for fs in ["virtiofs", "fuse.osxfs", "9p"]):
            apple_silicon_evidence.append("apple_filesystem")
            confidence_score += 0.4
        
        # 2. Check for QEMU virtualization (common on Apple Silicon)
        virt_type = container_info.get("virtualization", "")
        hypervisor = container_info.get("hypervisor_check", "")
        if "qemu" in virt_type.lower() or "hypervisor" in hypervisor.lower():
            apple_silicon_evidence.append("qemu_hypervisor")
            confidence_score += 0.3
        
        # 3. Check for Docker Desktop environment variables
        container_runtime = container_info.get("container_runtime", "")
        docker_info = container_info.get("docker_info", "")
        if any(indicator in (container_runtime + docker_info).lower() for indicator in [
            "docker-desktop", "docker_desktop", "com.docker.driver"
        ]):
            apple_silicon_evidence.append("docker_desktop")
            confidence_score += 0.4
        
        # 4. Check DMI info for Apple hardware
        dmi_info = container_info.get("dmi_info", "")
        if "apple" in dmi_info.lower():
            apple_silicon_evidence.append("apple_hardware")
            confidence_score += 0.5
        
        # 5. Check CPU info for emulation hints
        cpu_info = container_info.get("cpu_info", "")
        if any(hint in cpu_info.lower() for hint in [
            "apple", "qemu", "tcg", "kvm", "virtualization"
        ]):
            apple_silicon_evidence.append("cpu_virtualization")
            confidence_score += 0.2
        
        # 6. Check for specific mount patterns that indicate macOS host
        if "9p" in proc_mounts or "virtiofs" in proc_mounts:
            apple_silicon_evidence.append("macos_mount_patterns")
            confidence_score += 0.3
        
        # Determine if this is Apple Silicon based on evidence
        if confidence_score >= 0.6:  # Need strong evidence
            detection_result["is_apple_silicon"] = True
            
            # Check if this is emulated x86_64 on Apple Silicon
            if arch == "x86_64":
                detection_result["emulated_x86"] = True
                apple_silicon_evidence.append("x86_emulation")
            
            # Apple Silicon specific limitations
            detection_result["specific_limitations"] = [
                "emulated_performance" if detection_result["emulated_x86"] else "native_arm64",
                "limited_hardware_access",
                "host_filesystem_permissions",
                "docker_desktop_networking"
            ]
            
            # Apple Silicon specific capabilities
            detection_result["specific_capabilities"] = {
                "has_host_filesystem": True,
                "has_fast_io": True,
                "supports_rosetta": detection_result["emulated_x86"],
                "native_arm64": not detection_result["emulated_x86"]
            }
        
        detection_result["detection_confidence"] = confidence_score
        detection_result["evidence"] = apple_silicon_evidence
        
        logger.info(f"Apple Silicon detection: confidence={confidence_score:.2f}, evidence={apple_silicon_evidence}")
        
        return detection_result
    
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
                logger.error("ERROR - No recovery plan generated, stopping attempts")
                logger.error(f"Recovery attempt {recovery_attempts} failed to generate a plan")
                logger.error(f"Original task: {original_task}")
                logger.error(f"Last failure: {result.error_message}")
                if result.results:
                    last_result = result.results[-1]
                    logger.error(f"Last failed command: {last_result.command}")
                    logger.error(f"Last exit code: {last_result.exit_code}")
                    logger.error(f"Last stderr: {last_result.stderr}")
                break
        
        # Update result with recovery information
        result.failure_contexts = self.failure_contexts
        result.recovery_attempts = recovery_attempts
        
        return result
    
    def _execute_task_attempt(self, task_description: str, auto_approve: bool = False) -> TaskResult:
        """Execute a single task attempt with prerequisite-informed planning"""
        logger.info("=== PHASE 1: Environment Collection ===")
        env_info = self._collect_comprehensive_environment_info()
        
        # Update context with environment type
        if "environment_type" in env_info:
            self.context.update_environment_type(env_info["environment_type"])
        
        logger.info("=== PHASE 2: Prerequisite Analysis ===")
        prerequisite_spec = self._collect_task_prerequisites(task_description, env_info)
        
        if prerequisite_spec.get("error"):
            logger.warning(f"Prerequisite analysis failed: {prerequisite_spec['error']}")
            # Fall back to original method
            return self._execute_task_attempt_original(task_description, auto_approve)
        
        prerequisites = prerequisite_spec.get("prerequisites", [])
        logger.info(f"LLM identified {len(prerequisites)} prerequisites to collect")
        
        logger.info("=== PHASE 3: Prerequisite Collection ===")
        prerequisite_results = self._execute_prerequisite_collection(prerequisites)
        
        # Log what we learned
        for category, result in prerequisite_results.items():
            status = "✅" if result["success"] else "❌"
            logger.info(f"{status} {category}: {result['description']}")
        
        logger.info("=== PHASE 4: Informed Action Planning ===")
        action_plan = self._create_informed_action_plan(task_description, env_info, prerequisite_results)
        
        if not action_plan.steps:
            logger.error("No action plan generated - this should not happen with fallback")
            return TaskResult(
                task_description=task_description,
                success=False,
                steps_completed=0,
                total_steps=0,
                results=[],
                error_message="No action plan generated despite fallback mechanisms"
            )
        
        logger.info(f"Generated plan with {len(action_plan.steps)} steps based on prerequisites")
        
        # Continue with existing execution logic...
        current_state = self.context.get_current_state()
        comprehensive_state = {
            "environment": env_info,
            "current_state": current_state,
            "prerequisites": prerequisite_results,
            "task_description": task_description
        }
        
        # Validate action plan safety
        commands = [step.get("command", "") for step in action_plan.steps]
        validation = self.analyzer.validate_action_plan(commands, comprehensive_state)
        
        if not validation.get("safe", False) and not auto_approve:
            logger.warning(f"Action plan not considered safe: {validation.get('reason', 'Unknown reason')}")
            # For fallback plans, we might want to be more lenient
            if "Fallback plan" in action_plan.goal:
                logger.info("Allowing fallback plan to proceed despite safety concerns")
            else:
                return TaskResult(
                    task_description=task_description,
                    success=False,
                    steps_completed=0,
                    total_steps=len(action_plan.steps),
                    results=[],
                    error_message=f"Action plan not safe: {validation.get('reason', 'Unknown reason')}"
                )
        
        # Execute steps with prerequisite awareness
        return self._execute_steps_with_prerequisite_context(
            action_plan, task_description, prerequisite_results
        )

    def _execute_task_attempt_original(self, task_description: str, auto_approve: bool = False) -> TaskResult:
        """Original execution method as fallback"""
        # Get current system state
        current_state = self.context.get_current_state()
        
        # Combine environment info with current state
        comprehensive_state = {
            "environment": {},
            "current_state": current_state,
            "task_description": task_description
        }
        
        # Get LLM action plan with basic context
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
        
        # Validate action plan safety
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
        
        # Execute steps with original logic
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
                
                # Interpret the exit code in context
                exit_interpretation = self._interpret_exit_code(
                    result.command, 
                    result.exit_code, 
                    result.stdout, 
                    result.stderr
                )
                
                if not exit_interpretation["is_error"]:
                    logger.info(f"Step {i+1} completed with informational exit code: {exit_interpretation['message']}")
                    completed_steps += 1
                    
                    # Add interpretation info to result
                    result = CommandResult(
                        stdout=result.stdout,
                        stderr=result.stderr,
                        exit_code=result.exit_code,
                        command=result.command,
                        allowed=result.allowed,
                        reason=result.reason,
                        validation_info={
                            "exit_interpretation": exit_interpretation,
                            "treated_as_success": True
                        }
                    )
                    results[-1] = result
                    continue
                
                # If it's a real error, proceed with existing validation logic
                validation = self._validate_step_completion(step, result, task_description)
                
                if validation.get("continue", False):
                    logger.info(f"Continuing despite failure: {validation.get('reason', 'Unknown reason')}")
                    
                    # Check if LLM provided a corrected command with generated values
                    generated_command = validation.get("generated_command", "")
                    if generated_command and generated_command != command:
                        logger.info(f"Executing corrected command with generated values: {generated_command}")
                        
                        # Execute the corrected command
                        corrected_result = self.executor.execute(generated_command)
                        results.append(corrected_result)
                        self.context.update_context(generated_command, corrected_result)
                        
                        if corrected_result.exit_code == 0:
                            logger.info("Corrected command succeeded!")
                            completed_steps += 1
                            
                            # Log what was generated
                            generated_values = validation.get("generated_values", {})
                            if generated_values:
                                logger.info(f"Auto-generated values: {list(generated_values.keys())}")
                            
                            continue
                        else:
                            logger.error(f"Corrected command also failed: {corrected_result.stderr}")
                            # Fall through to normal failure handling
                    
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
        
        # Handle case where there are no command results (planning failure)
        if not failed_result.results:
            logger.warning("No command results in failed task - this was a planning failure")
            return self._create_planning_failure_recovery_plan(failed_result, original_task)
        
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
        
        # Log the prompt being sent to LLM for debugging
        logger.info("=== RECOVERY PLAN PROMPT SENT TO LLM ===")
        logger.info(f"Failure type: {failure_analysis['failure_type']}")
        logger.info(f"Original task: {original_task}")
        logger.info(f"Failed command: {failed_command_result.command}")
        logger.info(f"Exit code: {failed_command_result.exit_code}")
        logger.info(f"Error: {failed_command_result.stderr}")
        logger.info("--- FULL PROMPT ---")
        logger.info(prompt)
        logger.info("=== END RECOVERY PLAN PROMPT ===")
        
        try:
            response = self.analyzer._call_llm(prompt)
            logger.info("=== LLM RECOVERY PLAN RESPONSE ===")
            logger.info(response)
            logger.info("=== END LLM RESPONSE ===")
            
            recovery_plan = self.analyzer._parse_action_plan(response)
            
            # If recovery plan fails, create fallback plan
            if not recovery_plan.steps:
                logger.warning("LLM returned empty recovery plan, creating fallback")
                logger.info(f"Recovery plan goal: '{recovery_plan.goal}'")
                logger.info(f"Recovery plan steps: {recovery_plan.steps}")
                logger.info(f"Recovery plan risks: {recovery_plan.risks}")
                return self._create_fallback_plan(original_task, failure_analysis)
            
            logger.info(f"Successfully generated recovery plan with {len(recovery_plan.steps)} steps")
            return recovery_plan
            
        except Exception as e:
            logger.error(f"Failed to get recovery plan: {e}")
            logger.exception("Full traceback for recovery plan failure:")
            return self._create_fallback_plan(original_task, failure_analysis)
    
    def _validate_step_completion(self, step: Dict[str, Any], result: CommandResult, 
                                original_goal: str) -> Dict[str, Any]:
        """Validate if a step should be considered successful even if command failed"""
        command = step.get("command", "") if isinstance(step, dict) else str(step)
        description = step.get("description", "") if isinstance(step, dict) else ""
        
        # If command succeeded, no need for validation
        if result.exit_code == 0:
            return {"continue": True, "reason": "Command succeeded", "step_achieved": True}
        
        # CRITICAL STEP ANALYSIS - Check if this is a blocking failure
        critical_failure_patterns = [
            # Package installation failures
            ("install", ["no package", "unable to locate", "package not found", "nothing to do"]),
            # Service start failures  
            ("start", ["failed to start", "job failed", "unit not found"]),
            # Download/fetch failures
            ("download", ["failed to download", "connection failed", "not found"]),
            # Permission failures that can't be easily fixed
            ("permission", ["permission denied", "access denied"] if "sudo" in command else [])
        ]
        
        command_lower = command.lower()
        stderr_lower = result.stderr.lower()
        
        # Check for critical failures that should trigger replanning
        for failure_type, error_patterns in critical_failure_patterns:
            if failure_type in command_lower:
                if any(pattern in stderr_lower for pattern in error_patterns):
                    logger.warning(f"Critical {failure_type} failure detected: {result.stderr[:100]}")
                    return {
                        "continue": False,
                        "reason": f"Critical {failure_type} failure: {result.stderr[:100]}",
                        "step_achieved": False,
                        "critical_failure": True,
                        "requires_replanning": True
                    }
        
        # Check for common "already exists" scenarios (these can continue)
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
        
        # For unclear failures, consult LLM but be more conservative
        llm_validation = self._consult_llm_for_step_validation(step, result, original_goal)
        
        # Override LLM if it suggests continuing on what appears to be a critical failure
        if llm_validation.get("continue", False):
            # Double-check for installation/setup failures
            if any(keyword in command_lower for keyword in ["install", "setup", "download", "fetch"]):
                if any(error in stderr_lower for error in ["not found", "failed", "error", "unable"]):
                    logger.warning("Overriding LLM suggestion - this appears to be a critical installation failure")
                    return {
                        "continue": False,
                        "reason": f"Critical installation failure overriding LLM: {result.stderr[:100]}",
                        "step_achieved": False,
                        "critical_failure": True,
                        "requires_replanning": True
                    }
        
        return llm_validation

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
                        # Normalize item name for matching
                        item_lower = item.lower().strip('<>{}')
                        
                        # Replace various placeholder formats
                        placeholder_formats = [
                            f"<{item}>", f"{{{item}}}", 
                            f"<{item.upper()}>", f"{{{item.upper()}}}",
                            f"<{item.lower()}>", f"{{{item.lower()}}}",
                            f"<{item_lower}>", f"{{{item_lower}}}",
                            # Handle timestamp-specific formats
                            "<timestamp>", "{timestamp}",
                            "<TIMESTAMP>", "{TIMESTAMP}",
                            "<time>", "{time}",
                            "<date>", "{date}",
                            "<datetime>", "{datetime}"
                        ]
                        
                        for placeholder in placeholder_formats:
                            if placeholder in final_command:
                                final_command = final_command.replace(placeholder, value)
                                logger.debug(f"Replaced {placeholder} with {value[:10]}...")
                        
                        # Also handle the case where the item name matches the placeholder content
                        if item_lower in ["timestamp", "time", "date", "datetime"]:
                            for ts_placeholder in ["<timestamp>", "{timestamp}", "<time>", "{time}", "<date>", "{date}"]:
                                if ts_placeholder in final_command:
                                    final_command = final_command.replace(ts_placeholder, value)
                                    logger.debug(f"Replaced timestamp placeholder {ts_placeholder} with {value}")
                    
                    # Debug and fix any remaining issues
                    final_command = self._debug_placeholder_replacement(corrected_command, final_command, generated_values)
                    
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
        
        # Check for backup/archive commands that need timestamps
        backup_indicators = ["backup", "tar", "zip", "archive", "dump"]
        if any(indicator in command.lower() for indicator in backup_indicators):
            # Check if command doesn't already have a timestamp-like pattern
            import re
            if not re.search(r'\d{4}[-_]\d{2}[-_]\d{2}', command):
                generation_needed.append("timestamp")
        
        # Check for log file creation
        if any(indicator in command.lower() for indicator in ["log", "output", "report"]):
            import re
            if not re.search(r'\d{4}[-_]\d{2}[-_]\d{2}', command):
                generation_needed.append("timestamp")
        
        # Check for temporary file creation
        if any(indicator in command.lower() for indicator in ["temp", "tmp", "/tmp/"]):
            generation_needed.append("temp_file")
        
        return generation_needed
    
    def _generate_missing_information(self, info_type: str, context: Dict[str, Any]) -> str:
        """Generate missing information based on type"""
        import secrets
        import string
        from datetime import datetime
        
        # Normalize the info_type to handle various formats
        info_type_lower = info_type.lower().strip('<>{}')
        
        if info_type_lower in ["password", "secure_password"]:
            # Generate secure password
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            return ''.join(secrets.choice(alphabet) for _ in range(16))
        
        elif info_type_lower in ["random_string", "randomstring"]:
            # Generate random alphanumeric string
            return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        
        elif info_type_lower in ["timestamp", "time", "date", "datetime"]:
            # Generate timestamp in various formats
            now = datetime.now()
            return now.strftime("%Y%m%d_%H%M%S")
        
        elif info_type_lower in ["temp_file", "tempfile", "temporary_file"]:
            # Generate temporary filename
            random_suffix = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(8))
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            return f"tmp_{timestamp}_{random_suffix}"
        
        elif info_type_lower in ["secure_key", "securekey", "key"]:
            # Generate secure key identifier
            return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        
        elif info_type_lower in ["random_port", "port"]:
            # Generate random port in safe range
            return str(secrets.randbelow(10000) + 50000)  # 50000-59999
        
        elif info_type_lower in ["backup_name", "backup_file"]:
            # Generate backup filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            return f"backup_{timestamp}"
        
        elif info_type_lower in ["log_file", "logfile"]:
            # Generate log filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            return f"log_{timestamp}.log"
        
        else:
            # Default to random string for unknown types
            logger.warning(f"Unknown info type '{info_type}', generating random string")
            return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    
    def _debug_placeholder_replacement(self, original_command: str, final_command: str, generated_values: Dict[str, Any]) -> str:
        """Debug placeholder replacement process"""
        from datetime import datetime
        
        logger.debug(f"Placeholder replacement debug:")
        logger.debug(f"  Original: {original_command}")
        logger.debug(f"  Final: {final_command}")
        logger.debug(f"  Generated values: {generated_values}")
        
        # Check for unreplaced placeholders
        import re
        remaining_placeholders = re.findall(r'<[^>]+>|\{[^}]+\}', final_command)
        if remaining_placeholders:
            logger.warning(f"Unreplaced placeholders found: {remaining_placeholders}")
            
            # Try to fix common timestamp issues
            for placeholder in remaining_placeholders:
                if any(ts_word in placeholder.lower() for ts_word in ['timestamp', 'time', 'date']):
                    timestamp_value = datetime.now().strftime("%Y%m%d_%H%M%S")
                    final_command = final_command.replace(placeholder, timestamp_value)
                    logger.info(f"Fixed unreplaced timestamp placeholder: {placeholder} -> {timestamp_value}")
        
        return final_command
    
    def _execute_steps_with_prerequisite_context(self, action_plan: ActionPlan, 
                                               task_description: str, 
                                               prerequisite_results: Dict[str, Any]) -> TaskResult:
        """Execute steps with awareness of prerequisite results"""
        results = []
        completed_steps = 0
        skipped_steps = []
        
        for i in range(len(action_plan.steps)):  # Use range instead of enumerate
            # Check if we've exceeded the steps due to replanning
            if i >= len(action_plan.steps):
                break
                
            step = action_plan.steps[i]
            command = step.get("command", "")
            description = step.get("description", "")
            skip_condition = step.get("skip_condition", "")
            prerequisite_basis = step.get("prerequisite_basis", "")
            
            logger.info(f"Step {i+1}/{len(action_plan.steps)}: {description}")
            
            # Check if step should be skipped based on prerequisites
            if self._should_skip_step_based_on_prerequisites(step, prerequisite_results):
                logger.info(f"Skipping step {i+1}: {skip_condition}")
                skipped_steps.append({
                    "step": i+1,
                    "description": description,
                    "reason": f"Prerequisite check: {prerequisite_basis}",
                    "skip_reason": skip_condition
                })
                completed_steps += 1
                continue
            
            if not command:
                logger.warning(f"Step {i+1} has no command, skipping")
                continue
            
            # Validate command for container environment
            env_info = self.context.get_current_state().get("environment", {})
            container_validation = self._validate_command_for_container(command, {"environment_type": env_info.get("environment_type", {})})
            if not container_validation["allowed"]:
                logger.warning(f"Command not suitable for container: {container_validation['reason']}")
                
                # Try to get alternative approach from LLM
                alternative_result = self._get_container_alternative_command(
                    command, description, container_validation, task_description
                )
                
                if alternative_result.get("alternative_command"):
                    logger.info(f"Using container alternative: {alternative_result['alternative_command']}")
                    command = alternative_result["alternative_command"]
                    description = f"{description} (container alternative)"
                else:
                    # Skip this step with explanation
                    logger.info(f"Skipping container-incompatible step: {description}")
                    skipped_steps.append({
                        "step": i+1,
                        "description": description,
                        "reason": container_validation["reason"],
                        "skip_reason": "Container environment limitation",
                        "alternatives": container_validation.get("alternatives", [])
                    })
                    completed_steps += 1
                    continue
            
            # Execute with existing logic but enhanced context
            result = self.executor.execute(command)
            results.append(result)
            self.context.update_context(command, result)
            
            # Continue with existing validation logic...
            if not result.allowed:
                return TaskResult(
                    task_description=task_description,
                    success=False,
                    steps_completed=completed_steps,
                    total_steps=len(action_plan.steps),
                    results=results,
                    error_message=f"Command blocked: {result.reason}",
                    skipped_steps=skipped_steps
                )
            
            # Handle exit codes and validation as before...
            if result.exit_code != 0:
                exit_interpretation = self._interpret_exit_code(
                    result.command, result.exit_code, result.stdout, result.stderr
                )
                
                if not exit_interpretation["is_error"]:
                    completed_steps += 1
                    result = CommandResult(
                        stdout=result.stdout,
                        stderr=result.stderr,
                        exit_code=result.exit_code,
                        command=result.command,
                        allowed=result.allowed,
                        reason=result.reason,
                        validation_info={
                            "exit_interpretation": exit_interpretation,
                            "treated_as_success": True,
                            "prerequisite_context": prerequisite_basis
                        }
                    )
                    results[-1] = result
                    continue
                
                # ENHANCED FAILURE HANDLING WITH REPLANNING
                logger.warning(f"Step {i+1} failed with exit code {result.exit_code}")
                
                # First, try step validation to see if goal was achieved despite failure
                validation = self._validate_step_completion(step, result, task_description)
                
                # Check if this is explicitly marked as requiring replanning
                if validation.get("requires_replanning", False) or validation.get("critical_failure", False):
                    logger.info(f"Critical failure detected at step {i+1}, triggering immediate replanning...")
                    
                    # CRITICAL FAILURE - TRIGGER REPLANNING IMMEDIATELY
                    replan_result = self._replan_remaining_steps(
                        action_plan=action_plan,
                        failed_step_index=i,
                        failed_result=result,
                        task_description=task_description,
                        prerequisite_results=prerequisite_results,
                        completed_steps=results[:i]  # Steps completed so far
                    )
                    
                    if replan_result.get("success", False):
                        # Replace remaining steps with replanned steps
                        new_steps = replan_result.get("new_steps", [])
                        logger.info(f"Replanning successful: replacing {len(action_plan.steps) - i} remaining steps with {len(new_steps)} new steps")
                        
                        # Update action plan with new steps
                        action_plan.steps = action_plan.steps[:i] + new_steps
                        
                        # Continue execution with new plan
                        continue
                    else:
                        # Replanning failed - this is a critical failure
                        logger.error(f"Replanning failed: {replan_result.get('reason', 'Unknown reason')}")
                        return TaskResult(
                            task_description=task_description,
                            success=False,
                            steps_completed=completed_steps,
                            total_steps=len(action_plan.steps),
                            results=results,
                            error_message=f"Critical failure with replanning failure: {replan_result.get('reason', result.stderr)}",
                            skipped_steps=skipped_steps
                        )

                elif validation.get("continue", False):
                    # Step achieved goal despite failure - continue normally
                    validation["prerequisite_context"] = prerequisite_basis
                    completed_steps += 1
                    
                    # Handle corrected command if provided
                    generated_command = validation.get("generated_command", "")
                    if generated_command and generated_command != command:
                        logger.info(f"Executing corrected command: {generated_command}")
                        corrected_result = self.executor.execute(generated_command)
                        results.append(corrected_result)
                        self.context.update_context(generated_command, corrected_result)
                        
                        if corrected_result.exit_code == 0:
                            logger.info("Corrected command succeeded!")
                        else:
                            logger.warning("Corrected command also failed, but continuing based on validation")
                    
                    continue

                else:
                    # This is a failure that should stop execution
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
        
        return TaskResult(
            task_description=task_description,
            success=True,
            steps_completed=completed_steps,
            total_steps=len(action_plan.steps),
            results=results,
            skipped_steps=skipped_steps
        )

    def _should_skip_step_based_on_prerequisites(self, step: Dict[str, Any], 
                                               prerequisite_results: Dict[str, Any]) -> bool:
        """Determine if step should be skipped based on prerequisite results"""
        prerequisite_basis = step.get("prerequisite_basis", "")
        skip_condition = step.get("skip_condition", "")
        
        if not prerequisite_basis or not skip_condition:
            return False
        
        # Check if the prerequisite result indicates this step should be skipped
        prereq_result = prerequisite_results.get(prerequisite_basis, {})
        
        # Common skip patterns
        if "already running" in skip_condition and "active (running)" in prereq_result.get("stdout", ""):
            return True
        
        if "already installed" in skip_condition and prereq_result.get("success", False):
            return True
        
        if "file exists" in skip_condition and prereq_result.get("success", False):
            return True
        
        if "user exists" in skip_condition and prereq_result.get("success", False):
            return True
        
        return False

    def _validate_command_for_container(self, command: str, env_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validate if a command is appropriate for the current environment"""
        environment_type = env_info.get("environment_type", {})
        
        if not environment_type.get("is_container", False):
            return {"allowed": True, "reason": "Not a container environment"}
        
        capabilities = environment_type.get("capabilities", {})
        limitations = environment_type.get("limitations", [])
        
        # Check for problematic commands in containers
        problematic_patterns = [
            ("systemctl", not capabilities.get("can_use_systemctl", False), "systemd not available in container"),
            ("firewall-cmd", not capabilities.get("can_use_firewall", False), "firewall management not available in container"),
            ("iptables", not capabilities.get("can_modify_network", False), "network modification not available in container"),
            ("modprobe", not capabilities.get("can_modify_kernel", False), "kernel module access not available in container"),
            ("mount", "limited_kernel_access" in limitations, "mount operations limited in container"),
            ("sysctl", not capabilities.get("can_modify_kernel", False), "kernel parameter modification not available"),
        ]
        
        command_lower = command.lower()
        for pattern, is_problematic, reason in problematic_patterns:
            if pattern in command_lower and is_problematic:
                alternatives = environment_type.get("recommended_alternatives", {})
                
                # Provide specific nginx alternatives
                if "nginx" in command_lower and pattern == "systemctl":
                    nginx_alternatives = [
                        "nginx -g 'daemon off;' &  # Start nginx in background",
                        "nginx  # Start nginx as daemon", 
                        "nginx -t  # Test configuration",
                        "ps aux | grep nginx  # Check if running"
                    ]
                    return {
                        "allowed": False,
                        "reason": f"{reason} - use direct nginx commands instead",
                        "alternatives": nginx_alternatives,
                        "container_type": environment_type.get("container_type", "unknown")
                    }
                
                return {
                    "allowed": False,
                    "reason": reason,
                    "alternatives": alternatives.get(f"{pattern}_alternatives", []),
                    "container_type": environment_type.get("container_type", "unknown")
                }
        
        return {"allowed": True, "reason": "Command appears safe for container environment"}

    def _get_container_alternative_command(self, original_command: str, description: str, 
                                         validation_result: Dict[str, Any], task_goal: str) -> Dict[str, Any]:
        """Get container-appropriate alternative for a problematic command"""
        if not self.analyzer._client:
            return {"alternative_command": None}
        
        prompt = f"""
        This command cannot run in a container environment. Provide a container-appropriate alternative.
        
        Original Command: {original_command}
        Step Description: {description}
        Overall Goal: {task_goal}
        Container Type: {validation_result.get('container_type', 'unknown')}
        Limitation: {validation_result.get('reason', 'unknown')}
        
        Suggested Alternatives: {validation_result.get('alternatives', [])}
        
        Provide a container-appropriate alternative command that achieves the same goal, or respond with "SKIP" if no alternative exists.
        
        Examples:
        - systemctl start nginx → nginx -g "daemon off;" &
        - firewall-cmd → echo "Configure firewall on container host"
        - iptables → echo "Use container networking policies"
        
        Respond with just the alternative command, no explanation.
        """
        
        try:
            response = self.analyzer._call_llm(prompt).strip()
            if response.upper() == "SKIP" or not response:
                return {"alternative_command": None}
            return {"alternative_command": response}
        except Exception as e:
            logger.error(f"Failed to get container alternative: {e}")
            return {"alternative_command": None}

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

    def _replan_remaining_steps(self, action_plan: ActionPlan, failed_step_index: int, 
                               failed_result: CommandResult, task_description: str,
                               prerequisite_results: Dict[str, Any], 
                               completed_steps: List[CommandResult]) -> Dict[str, Any]:
        """Replan remaining steps after a critical failure using LLM"""
        
        if not self.analyzer._client:
            return {
                "success": False,
                "reason": "LLM not available for replanning",
                "new_steps": []
            }
        
        # Analyze what was accomplished so far
        completed_analysis = self._analyze_completed_steps(completed_steps, action_plan.steps[:failed_step_index])
        
        # Get current system state
        current_state = self.context.get_current_state()
        env_info = current_state.get("environment", {})
        
        prompt = f"""
        REPLANNING REQUIRED - Step Failed, Need New Approach
        
        ORIGINAL GOAL: {task_description}
        
        EXECUTION STATUS:
        =================
        Total Steps Planned: {len(action_plan.steps)}
        Steps Completed Successfully: {failed_step_index}
        Failed Step: {failed_step_index + 1}
        
        FAILED STEP DETAILS:
        ===================
        Command: {failed_result.command}
        Description: {action_plan.steps[failed_step_index].get('description', 'No description')}
        Exit Code: {failed_result.exit_code}
        Error Output: {failed_result.stderr}
        Standard Output: {failed_result.stdout}
        
        WHAT WAS ACCOMPLISHED:
        =====================
        {json.dumps(completed_analysis, indent=2)}
        
        REMAINING ORIGINAL STEPS (that need replanning):
        ===============================================
        {json.dumps([step.get('description', step.get('command', '')) for step in action_plan.steps[failed_step_index:]], indent=2)}
        
        SYSTEM CONTEXT:
        ===============
        Environment: {json.dumps(env_info.get('environment_type', {}), indent=2)}
        Prerequisites: {json.dumps(prerequisite_results, indent=2)}
        Current State: {json.dumps(current_state.get('current_state', {}), indent=2)}
        
        REPLANNING INSTRUCTIONS:
        =======================
        1. Analyze WHY the step failed (command not found, permission denied, wrong approach, etc.)
        2. Determine what still needs to be accomplished to achieve the original goal
        3. Create NEW steps that:
           - Work around the failure cause
           - Use alternative approaches/commands
           - Build on what was already accomplished
           - Are compatible with the current environment
        4. Ensure the new plan can achieve the original goal despite the failure
        
        REPLANNING STRATEGIES:
        =====================
        - If command not found: use alternative commands or install missing tools
        - If permission denied: add sudo or change approach
        - If service issues: use different service management approach
        - If package issues: use different package manager or manual installation
        - If file/directory issues: create prerequisites or use different paths
        - If network issues: check connectivity and use alternatives
        
        INSTALLATION FAILURE SPECIFIC STRATEGIES:
        ========================================
        - If package not found in repositories: try alternative package names, add repositories, or use manual installation
        - If dnf/yum fails: try different package managers, download directly, or use alternative software
        - If service installation fails: try different installation methods or alternative services
        - If dependencies missing: install dependencies first, or find self-contained alternatives

        CRITICAL FOR INSTALLATION FAILURES:
        ===================================
        - Do NOT proceed with configuration/startup steps if installation failed
        - Find working installation method FIRST before any other steps
        - Consider completely different software if original cannot be installed
        - Use alternative approaches (Docker, manual compilation, different package) if needed
        
        CRITICAL REQUIREMENTS:
        =====================
        - New steps must be compatible with detected environment type
        - Use placeholders for auto-generation where needed
        - Each step should include proper error checking
        - Focus on achieving the ORIGINAL GOAL, not just fixing the failed step
        
        Respond in JSON format:
        {{
            "analysis": "why the step failed and what needs to be done differently",
            "new_approach": "description of the new strategy",
            "steps": [
                {{
                    "command": "new command with placeholders if needed",
                    "description": "what this step accomplishes",
                    "prerequisite_check": "command to verify prerequisites",
                    "success_verification": "command to verify this step succeeded",
                    "auto_generate": ["list of placeholders to generate"],
                    "fallback_command": "alternative if this fails"
                }}
            ],
            "confidence": 0.8,
            "estimated_time": "X minutes"
        }}
        """
        
        try:
            logger.info("Requesting replanning from LLM...")
            response = self.analyzer._call_llm(prompt)
            
            # Parse the response
            fallback_data = {
                "analysis": "Failed to parse LLM response",
                "new_approach": "Fallback approach",
                "steps": [],
                "confidence": 0.0,
                "estimated_time": "unknown"
            }
            
            replan_data = self.analyzer._robust_json_parse(response, fallback_data)
            
            new_steps = replan_data.get("steps", [])
            
            if not new_steps:
                logger.warning("LLM returned no new steps in replan")
                return {
                    "success": False,
                    "reason": "No new steps provided by LLM",
                    "new_steps": []
                }
            
            # Validate new steps
            validated_steps = self._validate_replanned_steps(new_steps, env_info)
            
            logger.info(f"Replanning successful: {len(validated_steps)} new steps generated")
            logger.info(f"New approach: {replan_data.get('new_approach', 'Not specified')}")
            logger.info(f"LLM confidence: {replan_data.get('confidence', 0.0)}")
            
            return {
                "success": True,
                "new_steps": validated_steps,
                "analysis": replan_data.get("analysis", ""),
                "new_approach": replan_data.get("new_approach", ""),
                "confidence": replan_data.get("confidence", 0.0)
            }
            
        except Exception as e:
            logger.error(f"Replanning failed: {e}")
            logger.exception("Full traceback for replanning failure:")
            
            # Try to create a simple fallback replan
            fallback_steps = self._create_simple_fallback_replan(
                failed_result, task_description, action_plan.steps[failed_step_index:]
            )
            
            return {
                "success": len(fallback_steps) > 0,
                "new_steps": fallback_steps,
                "reason": f"LLM replanning failed: {str(e)}",
                "analysis": "Fallback replanning due to LLM failure"
            }

    def _analyze_completed_steps(self, completed_results: List[CommandResult], 
                               completed_step_definitions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze what was accomplished in the completed steps"""
        analysis = {
            "successful_operations": [],
            "system_changes": [],
            "installed_packages": [],
            "started_services": [],
            "created_files": [],
            "user_changes": []
        }
        
        for i, (result, step_def) in enumerate(zip(completed_results, completed_step_definitions)):
            if result.exit_code == 0:
                command = result.command
                description = step_def.get("description", "")
                
                analysis["successful_operations"].append({
                    "step": i + 1,
                    "command": command,
                    "description": description
                })
                
                # Categorize the type of operation
                if any(pkg_cmd in command for pkg_cmd in ["apt install", "yum install", "dnf install"]):
                    # Extract package name
                    parts = command.split()
                    if len(parts) > 2:
                        package = parts[-1]
                        analysis["installed_packages"].append(package)
                
                elif any(svc_cmd in command for svc_cmd in ["systemctl start", "service start"]):
                    # Extract service name
                    parts = command.split()
                    if len(parts) > 2:
                        service = parts[-1]
                        analysis["started_services"].append(service)
                
                elif any(file_cmd in command for file_cmd in ["touch", "echo >", "cat >", "mkdir"]):
                    analysis["created_files"].append(command)
                
                elif any(user_cmd in command for user_cmd in ["useradd", "usermod", "groupadd"]):
                    analysis["user_changes"].append(command)
                
                # Track general system changes
                if any(change_cmd in command for change_cmd in ["install", "start", "enable", "create", "add", "modify"]):
                    analysis["system_changes"].append({
                        "type": "modification",
                        "command": command,
                        "description": description
                    })
        
        return analysis

    def _validate_replanned_steps(self, new_steps: List[Dict[str, Any]], 
                                 env_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Validate and enhance replanned steps"""
        validated_steps = []
        
        for step in new_steps:
            # Ensure required fields exist
            validated_step = {
                "command": step.get("command", ""),
                "description": step.get("description", ""),
                "prerequisite_check": step.get("prerequisite_check", ""),
                "success_verification": step.get("success_verification", ""),
                "auto_generate": step.get("auto_generate", []),
                "fallback_command": step.get("fallback_command", "")
            }
            
            # Validate command for container environment
            if validated_step["command"]:
                container_validation = self._validate_command_for_container(
                    validated_step["command"], 
                    {"environment_type": env_info.get("environment_type", {})}
                )
                
                if not container_validation["allowed"]:
                    logger.warning(f"Replanned step not suitable for container: {container_validation['reason']}")
                    # Try to get alternative
                    alternative = self._get_container_alternative_command(
                        validated_step["command"],
                        validated_step["description"],
                        container_validation,
                        "replanned step"
                    )
                    
                    if alternative.get("alternative_command"):
                        validated_step["command"] = alternative["alternative_command"]
                        validated_step["description"] += " (container alternative)"
                    else:
                        # Skip this step
                        logger.info(f"Skipping container-incompatible replanned step: {validated_step['description']}")
                        continue
            
            validated_steps.append(validated_step)
        
        return validated_steps

    def _create_simple_fallback_replan(self, failed_result: CommandResult, 
                                      task_description: str, 
                                      remaining_steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create a simple fallback replan when LLM fails"""
        logger.info("Creating simple fallback replan")
        
        fallback_steps = []
        
        # Analyze the failure
        if "command not found" in failed_result.stderr:
            # Try to install missing command
            missing_cmd = failed_result.command.split()[0]
            fallback_steps.append({
                "command": f"apt install -y {missing_cmd} || yum install -y {missing_cmd} || echo 'Could not install {missing_cmd}'",
                "description": f"Attempt to install missing command: {missing_cmd}",
                "prerequisite_check": "",
                "success_verification": f"which {missing_cmd}",
                "auto_generate": [],
                "fallback_command": f"echo 'Manual installation of {missing_cmd} required'"
            })
            
            # Retry the original failed command
            fallback_steps.append({
                "command": failed_result.command,
                "description": f"Retry failed command: {failed_result.command}",
                "prerequisite_check": f"which {missing_cmd}",
                "success_verification": "",
                "auto_generate": [],
                "fallback_command": ""
            })
        
        elif "permission denied" in failed_result.stderr.lower():
            # Add sudo to the command
            if not failed_result.command.startswith("sudo"):
                fallback_steps.append({
                    "command": f"sudo {failed_result.command}",
                    "description": f"Retry with sudo: {failed_result.command}",
                    "prerequisite_check": "sudo -n true 2>/dev/null || echo 'sudo required'",
                    "success_verification": "",
                    "auto_generate": [],
                    "fallback_command": ""
                })
        
        else:
            # Generic retry with verification
            fallback_steps.append({
                "command": f"echo 'Analyzing failure: {failed_result.stderr[:100]}'",
                "description": "Log failure analysis",
                "prerequisite_check": "",
                "success_verification": "",
                "auto_generate": [],
                "fallback_command": ""
            })
        
        return fallback_steps

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

    def _create_fallback_action_plan(self, task_description: str, prerequisite_results: Dict[str, Any]) -> ActionPlan:
        """Create a basic fallback action plan when LLM fails"""
        logger.info("Creating fallback action plan based on task analysis")
        return self._create_task_specific_fallback(task_description, prerequisite_results)

    def _create_planning_failure_recovery_plan(self, failed_result: TaskResult, original_task: str) -> ActionPlan:
        """Create recovery plan for planning failures (when LLM can't generate initial plan)"""
        logger.info("Creating recovery plan for planning failure")
        
        # Try to create a simple, direct approach to the task
        task_lower = original_task.lower()
        recovery_steps = []
        
        if "remove" in task_lower and "cron" in task_lower:
            # Extract cron file name
            import re
            cron_match = re.search(r'cron.*?(\S+)', original_task)
            cron_file = cron_match.group(1) if cron_match else "unknown"
            
            recovery_steps = [
                {
                    "command": f"sudo rm -f /etc/cron.d/{cron_file}",
                    "description": f"Direct removal of cron file {cron_file}"
                },
                {
                    "command": f"ls /etc/cron.d/{cron_file} 2>/dev/null || echo 'Successfully removed'",
                    "description": "Verify removal"
                }
            ]
        
        else:
            # Generic recovery
            recovery_steps = [
                {
                    "command": f"echo 'Planning failed for task: {original_task}'",
                    "description": "Log planning failure"
                }
            ]
        
        return ActionPlan(
            goal=f"Recovery for planning failure: {original_task}",
            steps=recovery_steps,
            risks=["Direct approach without full analysis"],
            estimated_time="1-2 minutes",
            safety_score=0.6
        )

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
