import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
from .executor import CommandExecutor, CommandResult
from .llm_analyzer import ServerStateAnalyzer, ActionPlan
from .context_manager import ServerContext

logger = logging.getLogger(__name__)

class ExecutionPhase(Enum):
    UNDERSTANDING = "understanding"
    PREREQUISITE_COLLECTION = "prerequisite_collection"
    SAFEGUARD_CREATION = "safeguard_creation"
    PLAN_REFINEMENT = "plan_refinement"
    EXECUTION = "execution"
    VERIFICATION = "verification"
    ROLLBACK = "rollback"
    HUMAN_ESCALATION = "human_escalation"

@dataclass
class SystemSnapshot:
    """Comprehensive system snapshot for rollback"""
    timestamp: str
    packages: Dict[str, str]
    services: Dict[str, str]
    config_files: Dict[str, str]
    disk_usage: str
    running_processes: List[str]

@dataclass
class ExecutionAttempt:
    """Record of an execution attempt"""
    attempt_number: int
    timestamp: str
    plan: ActionPlan
    results: List[CommandResult]
    success: bool
    error_message: Optional[str]
    llm_feedback: Optional[str]
    skipped_steps: List[Dict[str, Any]] = None

@dataclass
class EnhancedTaskResult:
    """Enhanced result with full execution context"""
    task_description: str
    final_success: bool
    total_attempts: int
    execution_phases: List[str]
    attempts: List[ExecutionAttempt]
    snapshots: List[SystemSnapshot]
    human_escalation_required: bool
    rollback_performed: bool
    final_message: str

class EnhancedExecutor:
    """Enhanced executor with safeguards, retries, and LLM guidance"""
    
    def __init__(self, executor: CommandExecutor, analyzer: ServerStateAnalyzer, context: ServerContext):
        self.executor = executor
        self.analyzer = analyzer
        self.context = context
        self.max_attempts = 3
        self.snapshots: List[SystemSnapshot] = []
        
    def execute_enhanced_task(self, goal: str, auto_approve: bool = False, 
                            human_callback: Optional[callable] = None) -> EnhancedTaskResult:
        """Execute task with full safeguards and retry logic"""
        logger.info(f"Starting enhanced execution: {goal}")
        
        attempts = []
        phases = []
        rollback_performed = False
        human_escalation = False
        
        try:
            # Phase 1: Understanding
            phases.append(ExecutionPhase.UNDERSTANDING.value)
            understanding = self._understand_goal(goal)
            
            # Phase 2: Prerequisite Collection
            phases.append(ExecutionPhase.PREREQUISITE_COLLECTION.value)
            prerequisites = self._collect_prerequisites(understanding)
            
            # Phase 3: Safeguard Creation
            phases.append(ExecutionPhase.SAFEGUARD_CREATION.value)
            snapshot = self._create_safeguards()
            
            # Phase 4: Plan Refinement with LLM
            phases.append(ExecutionPhase.PLAN_REFINEMENT.value)
            initial_plan = self._create_refined_plan(goal, prerequisites)
            
            # Phase 5: Execution with retries
            phases.append(ExecutionPhase.EXECUTION.value)
            
            for attempt_num in range(1, self.max_attempts + 1):
                logger.info(f"Execution attempt {attempt_num}/{self.max_attempts}")
                
                attempt = self._execute_attempt(attempt_num, initial_plan, auto_approve)
                attempts.append(attempt)
                
                if attempt.success:
                    # Phase 6: Verification
                    phases.append(ExecutionPhase.VERIFICATION.value)
                    if self._verify_success(goal, attempt):
                        return EnhancedTaskResult(
                            task_description=goal,
                            final_success=True,
                            total_attempts=attempt_num,
                            execution_phases=phases,
                            attempts=attempts,
                            snapshots=self.snapshots,
                            human_escalation_required=False,
                            rollback_performed=False,
                            final_message="Task completed successfully"
                        )
                
                # Get LLM feedback for next attempt
                if attempt_num < self.max_attempts:
                    initial_plan = self._get_llm_feedback_and_replan(attempt, prerequisites)
            
            # All attempts failed - escalate to human or rollback
            if human_callback:
                phases.append(ExecutionPhase.HUMAN_ESCALATION.value)
                human_decision = human_callback(goal, attempts, prerequisites)
                
                if human_decision.get("continue", False):
                    # Human provided guidance, try once more
                    final_attempt = self._execute_with_human_guidance(
                        human_decision.get("guidance", ""), 
                        prerequisites, 
                        auto_approve
                    )
                    attempts.append(final_attempt)
                    
                    if final_attempt.success:
                        return EnhancedTaskResult(
                            task_description=goal,
                            final_success=True,
                            total_attempts=len(attempts),
                            execution_phases=phases,
                            attempts=attempts,
                            snapshots=self.snapshots,
                            human_escalation_required=True,
                            rollback_performed=False,
                            final_message="Task completed with human guidance"
                        )
                
                human_escalation = True
            
            # Rollback if configured
            if not auto_approve or human_escalation:
                phases.append(ExecutionPhase.ROLLBACK.value)
                rollback_performed = self._perform_rollback(snapshot)
            
            return EnhancedTaskResult(
                task_description=goal,
                final_success=False,
                total_attempts=len(attempts),
                execution_phases=phases,
                attempts=attempts,
                snapshots=self.snapshots,
                human_escalation_required=human_escalation,
                rollback_performed=rollback_performed,
                final_message="Task failed after all attempts"
            )
            
        except Exception as e:
            logger.error(f"Enhanced execution failed: {e}")
            
            # Emergency rollback
            if self.snapshots:
                phases.append(ExecutionPhase.ROLLBACK.value)
                rollback_performed = self._perform_rollback(self.snapshots[-1])
            
            return EnhancedTaskResult(
                task_description=goal,
                final_success=False,
                total_attempts=len(attempts),
                execution_phases=phases,
                attempts=attempts,
                snapshots=self.snapshots,
                human_escalation_required=True,
                rollback_performed=rollback_performed,
                final_message=f"Task failed with error: {str(e)}"
            )

    def _understand_goal(self, goal: str) -> Dict[str, Any]:
        """Use LLM to understand and break down the goal"""
        prompt = f"""
        Analyze this system administration goal and break it down:
        
        Goal: {goal}
        
        Provide:
        1. Goal category (package_management, service_management, configuration, security, etc.)
        2. Required system access level (read-only, read-write, root)
        3. Potential system components affected
        4. Risk level (low, medium, high, critical)
        5. Prerequisites that need to be checked
        
        Respond in JSON format.
        """
        
        try:
            response = self.analyzer._call_llm(prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"Goal understanding failed: {e}")
            return {
                "category": "unknown",
                "access_level": "read-write",
                "components": [],
                "risk_level": "medium",
                "prerequisites": []
            }
    
    def _collect_prerequisites(self, understanding: Dict[str, Any]) -> Dict[str, Any]:
        """Collect comprehensive system state and prerequisites"""
        # Use the smart executor's environment collection method
        from .smart_executor import SmartExecutor
        temp_smart_executor = SmartExecutor(self.executor, self.analyzer, self.context)
        env_info = temp_smart_executor._collect_comprehensive_environment_info()
        
        prerequisites = {
            "environment": env_info,
            "system_info": {},
            "package_state": {},
            "service_state": {},
            "disk_space": {},
            "network_connectivity": {},
            "permissions": {}
        }
        
        # Add basic system information
        system_commands = [
            "uname -a",
            "cat /etc/os-release",
            "df -h",
            "free -h",
            "whoami",
            "id",
            "pwd"
        ]
        
        for cmd in system_commands:
            result = self.executor.execute(cmd)
            if result.allowed and result.exit_code == 0:
                prerequisites["system_info"][cmd] = result.stdout
        
        # The environment info already contains package manager details
        prerequisites["package_state"] = env_info.get("package_manager", {})
        
        # Collect service information if needed
        if understanding.get("category") == "service_management":
            result = self.executor.execute("systemctl list-units --type=service --state=running")
            if result.allowed and result.exit_code == 0:
                prerequisites["service_state"]["running"] = result.stdout
        
        return prerequisites
    
    def _create_safeguards(self) -> SystemSnapshot:
        """Create comprehensive system snapshot"""
        timestamp = datetime.now().isoformat()
        
        # Get package list
        packages = {}
        pkg_result = self.executor.execute("dpkg -l 2>/dev/null || rpm -qa")
        if pkg_result.allowed and pkg_result.exit_code == 0:
            for line in pkg_result.stdout.split('\n')[:100]:  # Limit for performance
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        packages[parts[1]] = "installed"
        
        # Get service states
        services = {}
        svc_result = self.executor.execute("systemctl list-units --type=service --no-pager")
        if svc_result.allowed and svc_result.exit_code == 0:
            for line in svc_result.stdout.split('\n'):
                if '.service' in line and ('running' in line or 'failed' in line):
                    parts = line.split()
                    if len(parts) >= 4:
                        services[parts[0]] = parts[3]
        
        # Get disk usage
        disk_result = self.executor.execute("df -h")
        disk_usage = disk_result.stdout if disk_result.allowed else ""
        
        # Get running processes
        proc_result = self.executor.execute("ps aux")
        processes = proc_result.stdout.split('\n')[:50] if proc_result.allowed else []
        
        snapshot = SystemSnapshot(
            timestamp=timestamp,
            packages=packages,
            services=services,
            config_files={},  # Could be expanded to backup specific configs
            disk_usage=disk_usage,
            running_processes=processes
        )
        
        self.snapshots.append(snapshot)
        logger.info(f"Created system snapshot at {timestamp}")
        
        return snapshot
    
    def _create_refined_plan(self, goal: str, prerequisites: Dict[str, Any]) -> ActionPlan:
        """Create LLM-refined action plan with prerequisites"""
        prompt = f"""
        Create a detailed action plan for this goal with the current system state:
        
        Goal: {goal}
        
        System Prerequisites:
        {json.dumps(prerequisites, indent=2)}
        
        Create a safe, step-by-step plan that:
        1. Validates prerequisites
        2. Takes necessary safeguards
        3. Executes the goal
        4. Verifies success
        5. Includes rollback steps if needed
        
        Each step should include:
        - command: exact command to run
        - description: what this does
        - safety_check: verification command
        - rollback_command: how to undo if needed
        - risk_level: low/medium/high
        
        Respond in JSON format.
        """
        
        try:
            response = self.analyzer._call_llm(prompt)
            return self.analyzer._parse_action_plan(response)
        except Exception as e:
            logger.error(f"Plan refinement failed: {e}")
            return ActionPlan(
                goal=goal,
                steps=[],
                risks=[f"Planning failed: {str(e)}"],
                estimated_time="unknown",
                safety_score=0.0
            )

    def _execute_attempt(self, attempt_num: int, plan: ActionPlan, auto_approve: bool) -> ExecutionAttempt:
        """Execute a single attempt with intelligent validation"""
        return self._execute_with_intelligent_validation(plan, auto_approve)
    
    def _execute_with_intelligent_validation(self, plan: ActionPlan, auto_approve: bool) -> ExecutionAttempt:
        """Execute plan with intelligent step validation"""
        timestamp = datetime.now().isoformat()
        results = []
        skipped_steps = []
        
        for i, step in enumerate(plan.steps):
            command = step.get("command", "") if isinstance(step, dict) else str(step)
            description = step.get("description", "") if isinstance(step, dict) else ""
            
            if not command:
                continue
            
            # Execute prerequisite check if provided
            prereq_check = step.get("prerequisite_check", "") if isinstance(step, dict) else ""
            if prereq_check:
                prereq_result = self.executor.execute(prereq_check)
                if not prereq_result.allowed or prereq_result.exit_code != 0:
                    logger.warning(f"Prerequisite check failed: {prereq_check}")
                    # Check if prerequisite is actually already met
                    prereq_validation = self._validate_prerequisite_failure(prereq_check, prereq_result, command)
                    if not prereq_validation.get("continue", False):
                        return ExecutionAttempt(
                            attempt_number=1,
                            timestamp=timestamp,
                            plan=plan,
                            results=results,
                            success=False,
                            error_message=f"Prerequisite failed: {prereq_check}",
                            llm_feedback="Prerequisite validation failed"
                        )
            
            # Execute safety check if provided
            safety_check = step.get("safety_check", "") if isinstance(step, dict) else ""
            if safety_check:
                safety_result = self.executor.execute(safety_check)
                if not safety_result.allowed or safety_result.exit_code != 0:
                    logger.warning(f"Safety check failed: {safety_check}")
                    if not auto_approve:
                        return ExecutionAttempt(
                            attempt_number=1,
                            timestamp=timestamp,
                            plan=plan,
                            results=results,
                            success=False,
                            error_message=f"Safety check failed: {safety_check}",
                            llm_feedback="Safety validation failed"
                        )
            
            # Execute main command
            result = self.executor.execute(command)
            results.append(result)
            self.context.update_context(command, result)
            
            # Handle command failure with intelligent validation
            if not result.allowed or result.exit_code != 0:
                # Use smart executor's validation logic
                from .smart_executor import SmartExecutor
                temp_smart_executor = SmartExecutor(self.executor, self.analyzer, self.context)
                validation = temp_smart_executor._validate_step_completion(step, result, plan.goal)
                
                if validation.get("continue", False):
                    logger.info(f"Continuing despite failure: {validation.get('reason', 'Unknown reason')}")
                    
                    if validation.get("step_achieved", False):
                        skipped_steps.append({
                            "step": i+1,
                            "description": description,
                            "reason": validation.get("reason", ""),
                            "command": command
                        })
                    
                    continue
                else:
                    return ExecutionAttempt(
                        attempt_number=1,
                        timestamp=timestamp,
                        plan=plan,
                        results=results,
                        success=False,
                        error_message=f"Command failed: {command} - {validation.get('reason', result.stderr or result.reason)}",
                        llm_feedback=validation.get("reason", "")
                    )
            
            # Execute success verification if provided
            success_check = step.get("success_verification", "") if isinstance(step, dict) else ""
            if success_check:
                verify_result = self.executor.execute(success_check)
                if verify_result.exit_code != 0:
                    logger.warning(f"Success verification failed: {success_check}")
                    # This might not be a hard failure, but log it
        
        # Create successful attempt with skipped steps info
        attempt = ExecutionAttempt(
            attempt_number=1,
            timestamp=timestamp,
            plan=plan,
            results=results,
            success=True,
            error_message=None,
            llm_feedback=None
        )
        
        # Add skipped steps information
        attempt.skipped_steps = skipped_steps
        
        return attempt

    def _validate_prerequisite_failure(self, prereq_command: str, prereq_result: CommandResult, 
                                     target_command: str) -> Dict[str, Any]:
        """Validate if prerequisite failure should block execution"""
        prompt = f"""
        A prerequisite check failed before executing a command. Determine if this should block execution.
        
        Prerequisite Command: {prereq_command}
        Prerequisite Error: {prereq_result.stderr}
        Prerequisite Exit Code: {prereq_result.exit_code}
        Target Command: {target_command}
        
        Analyze:
        1. Is the prerequisite actually already satisfied?
        2. Is this prerequisite check overly strict?
        3. Can the target command still succeed?
        
        Common scenarios:
        - Checking if user exists before adding to group (user might already be in group)
        - Checking if package installed before configuring (package might be installed differently)
        - Checking if service running before restart (service might be stopped intentionally)
        
        Respond in JSON: {{"continue": true/false, "reason": "explanation", "confidence": 0.8}}
        """
        
        try:
            response = self.analyzer._call_llm(prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"Prerequisite validation failed: {e}")
            return {"continue": False, "reason": f"Validation failed: {str(e)}", "confidence": 0.0}
    
    def _get_llm_feedback_and_replan(self, failed_attempt: ExecutionAttempt, 
                                   prerequisites: Dict[str, Any]) -> ActionPlan:
        """Get LLM feedback and create new plan"""
        prompt = f"""
        The previous execution attempt failed. Analyze and create a better plan:
        
        Original Goal: {failed_attempt.plan.goal}
        
        Failed Attempt:
        - Error: {failed_attempt.error_message}
        - Commands executed: {[r.command for r in failed_attempt.results]}
        - Last command output: {failed_attempt.results[-1].stderr if failed_attempt.results else 'None'}
        
        System State:
        {json.dumps(prerequisites, indent=2)}
        
        Provide:
        1. Analysis of why it failed
        2. Alternative approach
        3. Modified action plan
        4. Additional safety measures
        
        Create a new action plan that addresses the failure.
        Respond in JSON format.
        """
        
        try:
            response = self.analyzer._call_llm(prompt)
            feedback_data = json.loads(response)
            failed_attempt.llm_feedback = feedback_data.get("analysis", "")
            
            return ActionPlan(
                goal=failed_attempt.plan.goal,
                steps=feedback_data.get("steps", []),
                risks=feedback_data.get("risks", []),
                estimated_time=feedback_data.get("estimated_time", "unknown"),
                safety_score=float(feedback_data.get("safety_score", 0.5))
            )
        except Exception as e:
            logger.error(f"LLM feedback failed: {e}")
            return failed_attempt.plan  # Return original plan as fallback
    
    def _verify_success(self, goal: str, attempt: ExecutionAttempt) -> bool:
        """Verify that the goal was actually achieved"""
        prompt = f"""
        Verify if this goal was successfully achieved:
        
        Goal: {goal}
        
        Commands executed:
        {[f"{r.command} (exit: {r.exit_code})" for r in attempt.results]}
        
        Last command outputs:
        {attempt.results[-1].stdout if attempt.results else 'None'}
        
        Based on the commands and outputs, was the goal successfully achieved?
        Respond with JSON: {{"success": true/false, "reason": "explanation"}}
        """
        
        try:
            response = self.analyzer._call_llm(prompt)
            verification = json.loads(response)
            return verification.get("success", False)
        except Exception as e:
            logger.error(f"Success verification failed: {e}")
            return len(attempt.results) > 0 and all(r.exit_code == 0 for r in attempt.results)
    
    def _execute_with_human_guidance(self, guidance: str, prerequisites: Dict[str, Any], 
                                   auto_approve: bool) -> ExecutionAttempt:
        """Execute with human-provided guidance"""
        prompt = f"""
        Create an action plan based on human guidance:
        
        Human Guidance: {guidance}
        
        System State:
        {json.dumps(prerequisites, indent=2)}
        
        Create a specific action plan following the human guidance.
        Respond in JSON format with steps.
        """
        
        try:
            response = self.analyzer._call_llm(prompt)
            plan_data = json.loads(response)
            
            guided_plan = ActionPlan(
                goal="Human-guided execution",
                steps=plan_data.get("steps", []),
                risks=plan_data.get("risks", []),
                estimated_time="unknown",
                safety_score=1.0  # Trust human guidance
            )
            
            return self._execute_attempt(99, guided_plan, auto_approve)
        except Exception as e:
            logger.error(f"Human-guided execution failed: {e}")
            return ExecutionAttempt(
                attempt_number=99,
                timestamp=datetime.now().isoformat(),
                plan=ActionPlan("Failed", [], [], "unknown", 0.0),
                results=[],
                success=False,
                error_message=f"Human guidance execution failed: {str(e)}",
                llm_feedback=None
            )
    
    def _perform_rollback(self, snapshot: SystemSnapshot) -> bool:
        """Perform system rollback to snapshot state"""
        logger.info(f"Performing rollback to snapshot: {snapshot.timestamp}")
        
        rollback_success = True
        
        # Rollback services
        for service, state in snapshot.services.items():
            if state == "running":
                result = self.executor.execute(f"systemctl start {service}")
                if result.exit_code != 0:
                    rollback_success = False
            elif state == "stopped":
                result = self.executor.execute(f"systemctl stop {service}")
                if result.exit_code != 0:
                    rollback_success = False
        
        # Note: Package rollback is complex and risky, so we log it but don't auto-execute
        logger.info("Package state rollback would require manual intervention")
        
        return rollback_success
