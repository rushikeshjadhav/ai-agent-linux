import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from .executor import CommandResult

logger = logging.getLogger(__name__)

@dataclass
class SystemSnapshot:
    """Snapshot of system state at a point in time"""
    timestamp: str
    cpu_usage: Optional[str] = None
    memory_usage: Optional[str] = None
    disk_usage: Optional[str] = None
    running_processes: Optional[str] = None
    network_connections: Optional[str] = None
    system_load: Optional[str] = None
    uptime: Optional[str] = None

class ServerContext:
    """Maintains understanding of server state"""
    
    def __init__(self):
        self.command_history: List[Dict[str, Any]] = []
        self.system_snapshots: List[SystemSnapshot] = []
        self.known_services: Dict[str, str] = {}
        self.known_packages: Dict[str, str] = {}
        self.current_state: Dict[str, Any] = {}
        self.last_analysis: Optional[Dict[str, Any]] = None
    
    def update_context(self, command: str, result: CommandResult):
        """Update server state understanding"""
        timestamp = datetime.now().isoformat()
        
        # Add to command history
        self.command_history.append({
            "timestamp": timestamp,
            "command": command,
            "exit_code": result.exit_code,
            "allowed": result.allowed,
            "stdout_length": len(result.stdout),
            "stderr_length": len(result.stderr)
        })
        
        # Keep only last 100 commands
        if len(self.command_history) > 100:
            self.command_history = self.command_history[-100:]
        
        # Extract system information from common commands
        self._extract_system_info(command, result)
        
        # Update current state
        self.current_state.update({
            "last_command": command,
            "last_command_time": timestamp,
            "last_exit_code": result.exit_code,
            "command_count": len(self.command_history)
        })
    
    def get_current_state(self) -> Dict[str, Any]:
        """Get current understanding of server state"""
        return {
            "current_state": self.current_state.copy(),
            "recent_commands": self.command_history[-10:],
            "known_services": self.known_services.copy(),
            "known_packages": self.known_packages.copy(),
            "last_snapshot": asdict(self.system_snapshots[-1]) if self.system_snapshots else None,
            "last_analysis": self.last_analysis
        }
    
    def create_system_snapshot(self, system_data: Dict[str, str]) -> SystemSnapshot:
        """Create a system snapshot from collected data"""
        timestamp = datetime.now().isoformat()
        
        snapshot = SystemSnapshot(
            timestamp=timestamp,
            cpu_usage=system_data.get("top", "")[:500],
            memory_usage=system_data.get("free -h", ""),
            disk_usage=system_data.get("df -h", ""),
            running_processes=system_data.get("ps aux", "")[:1000],
            network_connections=system_data.get("netstat -tuln", ""),
            system_load=system_data.get("uptime", ""),
            uptime=system_data.get("uptime", "")
        )
        
        self.system_snapshots.append(snapshot)
        
        # Keep only last 10 snapshots
        if len(self.system_snapshots) > 10:
            self.system_snapshots = self.system_snapshots[-10:]
        
        return snapshot
    
    def update_analysis(self, analysis_result: Dict[str, Any]):
        """Update the last analysis result"""
        self.last_analysis = {
            "timestamp": datetime.now().isoformat(),
            "result": analysis_result
        }
    
    def get_system_health_commands(self) -> List[str]:
        """Get list of commands to collect system health data"""
        return [
            "uptime",
            "free -h",
            "df -h",
            "ps aux | head -20",
            "top -bn1 | head -20",
            "netstat -tuln | head -10",
            "systemctl --failed",
            "dmesg | tail -10",
            "who",
            "last | head -5"
        ]
    
    def _extract_system_info(self, command: str, result: CommandResult):
        """Extract useful information from command results"""
        if not result.allowed or result.exit_code != 0:
            return
        
        stdout = result.stdout.strip()
        
        # Extract service information
        if command.startswith("systemctl status"):
            service_name = command.split()[-1]
            if "active (running)" in stdout:
                self.known_services[service_name] = "running"
            elif "inactive (dead)" in stdout:
                self.known_services[service_name] = "stopped"
            elif "failed" in stdout:
                self.known_services[service_name] = "failed"
        
        # Extract package information
        elif command.startswith("dpkg -l") or command.startswith("rpm -qa"):
            # Parse package list (simplified)
            for line in stdout.split('\n')[:50]:  # Limit parsing
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        package_name = parts[1] if command.startswith("dpkg") else parts[0]
                        self.known_packages[package_name] = "installed"
        
        # Extract disk usage
        elif command == "df -h":
            self.current_state["disk_usage"] = stdout
        
        # Extract memory usage
        elif command == "free -h":
            self.current_state["memory_usage"] = stdout
        
        # Extract system load
        elif command == "uptime":
            self.current_state["uptime"] = stdout
    
    def get_context_summary(self) -> str:
        """Get a human-readable summary of current context"""
        summary = []
        
        if self.command_history:
            summary.append(f"Commands executed: {len(self.command_history)}")
            recent_failures = sum(1 for cmd in self.command_history[-10:] if cmd["exit_code"] != 0)
            if recent_failures > 0:
                summary.append(f"Recent failures: {recent_failures}/10")
        
        if self.known_services:
            running_services = sum(1 for status in self.known_services.values() if status == "running")
            summary.append(f"Known services: {len(self.known_services)} ({running_services} running)")
        
        if self.system_snapshots:
            summary.append(f"System snapshots: {len(self.system_snapshots)}")
        
        if self.last_analysis:
            summary.append(f"Last analysis: {self.last_analysis['timestamp']}")
        
        return "; ".join(summary) if summary else "No context data available"
