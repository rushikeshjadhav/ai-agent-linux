from enum import Enum
from typing import Set, List
import re

class AgentMode(Enum):
    READ_ONLY = "ro"
    READ_WRITE = "rw"
    INTELLIGENT = "smart"

class CommandValidator:
    """Validates commands based on agent mode"""
    
    # Safe read-only commands
    RO_ALLOWED_COMMANDS = {
        'ls', 'cat', 'head', 'tail', 'grep', 'find', 'ps', 'top', 'df', 'du',
        'free', 'uptime', 'whoami', 'id', 'pwd', 'which', 'whereis', 'file',
        'stat', 'wc', 'sort', 'uniq', 'cut', 'awk', 'sed', 'less', 'more',
        'history', 'date', 'uname', 'hostname', 'mount', 'lsof', 'netstat',
        'ss', 'ping', 'traceroute', 'nslookup', 'dig', 'curl', 'wget'
    }
    
    # Dangerous commands that are never allowed in RO mode
    RO_BLOCKED_PATTERNS = [
        r'rm\s+.*-rf',  # rm -rf
        r'>\s*/',       # redirect to root
        r'sudo',        # sudo commands
        r'su\s',        # switch user
        r'chmod',       # change permissions
        r'chown',       # change ownership
        r'mv\s+.*\s+/', # move to system dirs
        r'cp\s+.*\s+/', # copy to system dirs
        r'dd\s',        # disk operations
        r'mkfs',        # filesystem creation
        r'fdisk',       # disk partitioning
        r'mount',       # mounting filesystems
        r'umount',      # unmounting
        r'systemctl',   # systemd control
        r'service',     # service control
        r'kill',        # process killing
        r'pkill',       # process killing
        r'killall',     # process killing
    ]
    
    def __init__(self, mode: AgentMode):
        self.mode = mode
        self.blocked_patterns = [re.compile(pattern, re.IGNORECASE) 
                               for pattern in self.RO_BLOCKED_PATTERNS]
    
    def is_command_allowed(self, command: str) -> tuple[bool, str]:
        """
        Check if command is allowed in current mode
        Returns (allowed, reason)
        """
        command = command.strip()
        
        if not command:
            return False, "Empty command"
        
        if self.mode in [AgentMode.READ_WRITE, AgentMode.INTELLIGENT]:
            # In RW and INTELLIGENT modes, all commands are allowed
            return True, f"{self.mode.value} mode allows all commands"
        
        # RO mode validation
        first_word = command.split()[0]
        
        # Check if base command is in allowed list
        if first_word not in self.RO_ALLOWED_COMMANDS:
            return False, f"Command '{first_word}' not allowed in RO mode"
        
        # Check against blocked patterns
        for pattern in self.blocked_patterns:
            if pattern.search(command):
                return False, f"Command matches blocked pattern in RO mode"
        
        return True, "Command allowed in RO mode"
