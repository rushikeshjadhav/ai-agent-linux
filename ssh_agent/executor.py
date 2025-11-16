import logging
from typing import NamedTuple, Optional, Dict
from .connection import SSHConnection
from .modes import AgentMode, CommandValidator

logger = logging.getLogger(__name__)

class CommandResult(NamedTuple):
    """Result of command execution"""
    stdout: str
    stderr: str
    exit_code: int
    command: str
    allowed: bool
    reason: str
    validation_info: Optional[Dict] = None

class CommandExecutor:
    """Executes commands on remote hosts with mode-based restrictions"""
    
    def __init__(self, connection: SSHConnection, mode: AgentMode):
        self.connection = connection
        self.mode = mode
        self.validator = CommandValidator(mode)
    
    def execute(self, command: str, timeout: int = 30) -> CommandResult:
        """Execute a command with mode validation"""
        
        # Validate command against current mode
        allowed, reason = self.validator.is_command_allowed(command)
        
        if not allowed:
            logger.warning(f"Command blocked: {command} - {reason}")
            return CommandResult(
                stdout="",
                stderr=f"Command blocked: {reason}",
                exit_code=-1,
                command=command,
                allowed=False,
                reason=reason,
                validation_info=None
            )
        
        # Check connection
        if not self.connection.connected:
            return CommandResult(
                stdout="",
                stderr="Not connected to remote host",
                exit_code=-1,
                command=command,
                allowed=True,
                reason="Connection error",
                validation_info=None
            )
        
        try:
            # Execute command
            stdin, stdout, stderr = self.connection.client.exec_command(
                command, timeout=timeout
            )
            
            # Get results
            stdout_data = stdout.read().decode('utf-8')
            stderr_data = stderr.read().decode('utf-8')
            exit_code = stdout.channel.recv_exit_status()
            
            logger.info(f"Executed: {command} (exit: {exit_code})")
            
            return CommandResult(
                stdout=stdout_data,
                stderr=stderr_data,
                exit_code=exit_code,
                command=command,
                allowed=True,
                reason="Command executed successfully",
                validation_info=None
            )
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return CommandResult(
                stdout="",
                stderr=f"Execution error: {str(e)}",
                exit_code=-1,
                command=command,
                allowed=True,
                reason=f"Execution error: {str(e)}",
                validation_info=None
            )
    
    def execute_with_context(self, command: str, context: dict = None, timeout: int = 30) -> CommandResult:
        """Execute command with LLM context analysis"""
        # For now, this is the same as regular execute
        # In the future, we could use context to modify command behavior
        result = self.execute(command, timeout)
        
        # Log context information if provided
        if context:
            logger.debug(f"Command executed with context: {context}")
        
        return result
