#!/usr/bin/env python3
"""
Example usage of the SSH Agent
"""

import logging
from ssh_agent import SSHAgent, AgentMode

# Configure logging
logging.basicConfig(level=logging.INFO)

def main():
    # Create agent in read-only mode
    agent = SSHAgent("example.com", "myuser", mode=AgentMode.READ_ONLY)
    
    try:
        # Connect using SSH key
        if agent.connect_with_key("~/.ssh/id_rsa"):
            print(f"Connected: {agent}")
            
            # Try some read-only commands
            commands = [
                "ls -la",
                "ps aux",
                "df -h",
                "rm -rf /",  # This should be blocked
                "sudo reboot"  # This should be blocked
            ]
            
            for cmd in commands:
                print(f"\n--- Executing: {cmd} ---")
                result = agent.execute_command(cmd)
                
                if result.allowed:
                    print(f"Exit code: {result.exit_code}")
                    if result.stdout:
                        print(f"STDOUT:\n{result.stdout}")
                    if result.stderr:
                        print(f"STDERR:\n{result.stderr}")
                else:
                    print(f"BLOCKED: {result.reason}")
            
            # Switch to read-write mode
            print("\n=== Switching to READ-write mode ===")
            agent.set_mode(AgentMode.READ_WRITE)
            
            # Now dangerous commands would be allowed (but don't actually run them!)
            result = agent.execute_command("echo 'This would be allowed in RW mode'")
            print(f"RW mode result: {result.stdout.strip()}")
            
        else:
            print("Failed to connect")
            
    finally:
        agent.disconnect()

if __name__ == "__main__":
    main()
