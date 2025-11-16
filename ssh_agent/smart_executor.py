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
        if not failed_result.results:
            logger.warning("No results in failed_result, cannot generate recovery plan")
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
