import paramiko
import logging
from typing import Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)

class SSHConnection:
    """Manages SSH connections with key or password authentication"""
    
    def __init__(self, hostname: str, username: str, port: int = 22):
        self.hostname = hostname
        self.username = username
        self.port = port
        self.client: Optional[paramiko.SSHClient] = None
        self.connected = False
    
    def connect_with_key(self, key_path: Union[str, Path], passphrase: Optional[str] = None) -> bool:
        """Connect using SSH key authentication"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            key_path = Path(key_path)
            if not key_path.exists():
                raise FileNotFoundError(f"SSH key not found: {key_path}")
            
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                key_filename=str(key_path),
                passphrase=passphrase,
                timeout=30
            )
            
            self.connected = True
            logger.info(f"Connected to {self.hostname} using SSH key")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect with SSH key: {e}")
            self.disconnect()
            return False
    
    def connect_with_password(self, password: str) -> bool:
        """Connect using password authentication"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=password,
                timeout=30
            )
            
            self.connected = True
            logger.info(f"Connected to {self.hostname} using password")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect with password: {e}")
            self.disconnect()
            return False
    
    def disconnect(self):
        """Close the SSH connection"""
        if self.client:
            self.client.close()
            self.connected = False
            logger.info(f"Disconnected from {self.hostname}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
