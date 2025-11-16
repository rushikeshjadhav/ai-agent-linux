import logging
from typing import NamedTuple, Optional
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
                reason=reason
            )
        
        # Check connection
        if not self.connection.connected:
            return CommandResult(
                stdout="",
                stderr="Not connected to remote host",
                exit_code=-1,
                command=command,
                allowed=True,
                reason="Connection error"
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
                reason="Command executed successfully"
            )
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return CommandResult(
                stdout="",
                stderr=f"Execution error: {str(e)}",
                exit_code=-1,
                command=command,
                allowed=True,
                reason=f"Execution error: {str(e)}"
            )
