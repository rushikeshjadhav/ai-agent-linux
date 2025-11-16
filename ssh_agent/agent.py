import logging
from typing import Optional, Union
from pathlib import Path
from .connection import SSHConnection
from .executor import CommandExecutor, CommandResult
from .modes import AgentMode

logger = logging.getLogger(__name__)

class SSHAgent:
    """Main SSH Agent class that combines connection, mode, and execution"""
    
    def __init__(self, hostname: str, username: str, mode: AgentMode = AgentMode.READ_ONLY, port: int = 22):
        self.hostname = hostname
        self.username = username
        self.mode = mode
        self.port = port
        
        self.connection = SSHConnection(hostname, username, port)
        self.executor: Optional[CommandExecutor] = None
        self.connected = False
    
    def connect_with_key(self, key_path: Union[str, Path], passphrase: Optional[str] = None) -> bool:
        """Connect using SSH key authentication"""
        success = self.connection.connect_with_key(key_path, passphrase)
        if success:
            self.executor = CommandExecutor(self.connection, self.mode)
            self.connected = True
        return success
    
    def connect_with_password(self, password: str) -> bool:
        """Connect using password authentication"""
        success = self.connection.connect_with_password(password)
        if success:
            self.executor = CommandExecutor(self.connection, self.mode)
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
        
        return self.executor.execute(command, timeout)
    
    def set_mode(self, mode: AgentMode):
        """Change the agent mode"""
        self.mode = mode
        if self.executor:
            self.executor = CommandExecutor(self.connection, self.mode)
        logger.info(f"Agent mode changed to {mode.value}")
    
    def disconnect(self):
        """Disconnect from remote host"""
        self.connection.disconnect()
        self.executor = None
        self.connected = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
    
    def __repr__(self):
        status = "connected" if self.connected else "disconnected"
        return f"SSHAgent({self.username}@{self.hostname}:{self.port}, mode={self.mode.value}, {status})"
