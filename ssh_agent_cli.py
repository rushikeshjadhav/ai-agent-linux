#!/usr/bin/env python3
"""
Interactive SSH Agent CLI
Supports SSH key authentication or password authentication
Allows users to specify tasks and execute them intelligently
"""

import os
import sys
import argparse
import getpass
from pathlib import Path
from typing import Optional, List
import logging

from ssh_agent import SSHAgent, AgentMode, LLMProvider

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SSHAgentCLI:
    """Interactive CLI for SSH Agent"""
    
    def __init__(self):
        self.agent: Optional[SSHAgent] = None
        self.connected = False
    
    def find_ssh_keys(self) -> List[Path]:
        """Find available SSH keys in ~/.ssh/"""
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            return []
        
        key_files = []
        for key_type in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]:
            key_path = ssh_dir / key_type
            if key_path.exists() and key_path.is_file():
                key_files.append(key_path)
        
        return key_files
    
    def prompt_connection_method(self) -> str:
        """Ask user how they want to connect"""
        print("\n🔐 Connection Methods:")
        print("1. Use SSH key")
        print("2. Use password")
        
        while True:
            choice = input("Choose connection method (1-2): ").strip()
            if choice in ["1", "2"]:
                return choice
            print("❌ Invalid choice. Please enter 1 or 2.")
    
    def prompt_ssh_key(self) -> Optional[Path]:
        """Let user choose an SSH key"""
        keys = self.find_ssh_keys()
        
        if not keys:
            print("❌ No SSH keys found in ~/.ssh/")
            return None
        
        print("\n🔑 Available SSH keys:")
        for i, key in enumerate(keys, 1):
            print(f"{i}. {key}")
        print(f"{len(keys) + 1}. Enter custom path")
        
        while True:
            try:
                choice = input(f"Choose SSH key (1-{len(keys) + 1}): ").strip()
                
                if choice == str(len(keys) + 1):
                    custom_path = input("Enter SSH key path: ").strip()
                    key_path = Path(custom_path).expanduser()
                    if key_path.exists():
                        return key_path
                    else:
                        print(f"❌ Key file not found: {key_path}")
                        continue
                
                idx = int(choice) - 1
                if 0 <= idx < len(keys):
                    return keys[idx]
                else:
                    print(f"❌ Invalid choice. Please enter 1-{len(keys) + 1}.")
            except ValueError:
                print(f"❌ Invalid input. Please enter a number 1-{len(keys) + 1}.")
    
    def prompt_server_details(self) -> tuple[str, str, int]:
        """Get server connection details"""
        print("\n🌐 Server Details:")
        hostname = input("Enter hostname/IP: ").strip()
        username = input("Enter username: ").strip()
        
        port_input = input("Enter port (default 22): ").strip()
        port = 22
        if port_input:
            try:
                port = int(port_input)
            except ValueError:
                print("⚠️ Invalid port, using default 22")
                port = 22
        
        return hostname, username, port
    
    def prompt_agent_mode(self) -> AgentMode:
        """Let user choose agent mode"""
        print("\n🤖 Agent Modes:")
        print("1. Read-Only (safe, limited commands)")
        print("2. Read-Write (full access)")
        print("3. Intelligent (LLM-guided operations)")
        
        while True:
            choice = input("Choose mode (1-3, default 1): ").strip()
            if not choice:
                choice = "1"
            
            if choice == "1":
                return AgentMode.READ_ONLY
            elif choice == "2":
                return AgentMode.READ_WRITE
            elif choice == "3":
                return AgentMode.INTELLIGENT
            else:
                print("❌ Invalid choice. Please enter 1, 2, or 3.")
    
    def connect_to_server(self, args=None) -> bool:
        """Handle server connection"""
        if args and hasattr(args, 'hostname') and args.hostname and hasattr(args, 'username') and args.username:
            # Use CLI arguments
            hostname = args.hostname
            username = args.username
            port = args.port
            
            # Convert mode string to enum
            mode_map = {
                "ro": AgentMode.READ_ONLY,
                "rw": AgentMode.READ_WRITE,
                "smart": AgentMode.INTELLIGENT
            }
            mode = mode_map[args.mode]
        else:
            # Use interactive prompts
            hostname, username, port = self.prompt_server_details()
            mode = self.prompt_agent_mode()
        
        # Auto-detect LLM provider based on available API keys
        llm_provider = None
        llm_api_key = None
        
        if os.getenv("OPENAI_API_KEY"):
            llm_provider = LLMProvider.OPENAI
            llm_api_key = os.getenv("OPENAI_API_KEY")
            print("🤖 Using OpenAI for LLM features")
        elif os.getenv("ANTHROPIC_API_KEY"):
            llm_provider = LLMProvider.ANTHROPIC
            llm_api_key = os.getenv("ANTHROPIC_API_KEY")
            print("🤖 Using Anthropic for LLM features")
        elif mode == AgentMode.INTELLIGENT:
            print("⚠️ Warning: No LLM API key found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY for full intelligent features.")
            print("🔄 Falling back to OpenAI provider (will fail without API key)")
            llm_provider = LLMProvider.OPENAI
        
        # Create agent with detected LLM provider
        self.agent = SSHAgent(hostname, username, mode, port, llm_provider, llm_api_key)
        
        print(f"\n🔌 Connecting to {username}@{hostname}:{port}...")
        
        # Determine connection method
        if args and hasattr(args, 'key') and args.key:
            # Use specified SSH key
            key_path = Path(args.key).expanduser()
            if not key_path.exists():
                print(f"❌ SSH key not found: {key_path}")
                return False
            
            passphrase = None
            if input(f"Does {key_path.name} have a passphrase? (y/N): ").lower().startswith('y'):
                passphrase = getpass.getpass("Enter passphrase: ")
            
            success = self.agent.connect_with_key(key_path, passphrase)
            
        elif args and hasattr(args, 'password') and args.password:
            # Use password authentication
            password = getpass.getpass("Enter password: ")
            success = self.agent.connect_with_password(password)
            
        else:
            # Interactive method selection
            method = self.prompt_connection_method()
            
            if method == "1":  # SSH key
                key_path = self.prompt_ssh_key()
                if not key_path:
                    return False
                
                passphrase = None
                if input(f"Does {key_path.name} have a passphrase? (y/N): ").lower().startswith('y'):
                    passphrase = getpass.getpass("Enter passphrase: ")
                
                success = self.agent.connect_with_key(key_path, passphrase)
                
            else:  # Password
                password = getpass.getpass("Enter password: ")
                success = self.agent.connect_with_password(password)
        
        if success:
            print(f"✅ Connected successfully!")
            print(f"📊 Agent: {self.agent}")
            self.connected = True
            return True
        else:
            print("❌ Connection failed!")
            return False
    
    def execute_task(self, task: str, auto_approve: bool = False):
        """Execute a user-specified task"""
        if not self.connected or not self.agent:
            print("❌ Not connected to server")
            return
        
        print(f"\n🎯 Executing task: {task}")
        
        # For intelligent mode, use smart execution
        if self.agent.mode == AgentMode.INTELLIGENT:
            print("🧠 Using intelligent execution...")
            
            # Use provided auto_approve or ask for approval
            if not auto_approve:
                auto_approve = input("Auto-approve all steps? (y/N): ").lower().startswith('y')
            
            result = self.agent.execute_smart_action(task, auto_approve)
            
            print(f"📋 Task: {result.task_description}")
            print(f"✅ Success: {result.success}")
            print(f"📊 Steps completed: {result.steps_completed}/{result.total_steps}")
            
            if result.error_message:
                print(f"❌ Error: {result.error_message}")
            
            # Show command results
            if result.results:
                print("\n📝 Command Results:")
                for i, cmd_result in enumerate(result.results, 1):
                    status = "✅" if cmd_result.exit_code == 0 else "❌"
                    print(f"  {i}. {status} {cmd_result.command}")
                    if cmd_result.exit_code != 0:
                        print(f"     Error: {cmd_result.stderr[:100]}...")
        
        else:
            # For other modes, treat as direct command
            print("🔧 Executing as direct command...")
            result = self.agent.execute_command(task)
            
            if result.allowed:
                if result.exit_code == 0:
                    print("✅ Command executed successfully")
                    if result.stdout:
                        print(f"📤 Output:\n{result.stdout}")
                else:
                    print(f"❌ Command failed (exit code {result.exit_code})")
                    if result.stderr:
                        print(f"📤 Error:\n{result.stderr}")
            else:
                print(f"🚫 Command blocked: {result.reason}")
    
    def interactive_session(self):
        """Run interactive session"""
        print("🎮 Interactive mode - Enter tasks or commands")
        print("Commands: 'health', 'context', 'mode <ro|rw|smart>', 'quit'")
        
        while True:
            try:
                task = input("\n💬 Enter task/command: ").strip()
                
                if not task:
                    continue
                
                if task.lower() in ['quit', 'exit', 'q']:
                    break
                
                elif task.lower() == 'health':
                    if not (os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")):
                        print("❌ Health analysis requires an LLM API key (OPENAI_API_KEY or ANTHROPIC_API_KEY)")
                        continue
                    
                    print("🏥 Analyzing server health...")
                    try:
                        analysis = self.agent.analyze_server_health()
                        print(f"📋 Summary: {analysis.summary}")
                        print(f"⚠️ Severity: {analysis.severity}")
                        print(f"🎯 Confidence: {analysis.confidence}")
                        
                        if analysis.issues:
                            print("🚨 Issues:")
                            for issue in analysis.issues:
                                print(f"  - {issue}")
                        
                        if analysis.recommendations:
                            print("💡 Recommendations:")
                            for rec in analysis.recommendations:
                                print(f"  - {rec}")
                    except Exception as e:
                        print(f"❌ Health analysis failed: {e}")
                
                elif task.lower() == 'context':
                    print("📊 Server Context:")
                    print(self.agent.get_context_summary())
                
                elif task.lower().startswith('mode '):
                    mode_str = task.split(' ', 1)[1].lower()
                    if mode_str == 'ro':
                        self.agent.set_mode(AgentMode.READ_ONLY)
                        print("🔒 Switched to Read-Only mode")
                    elif mode_str == 'rw':
                        self.agent.set_mode(AgentMode.READ_WRITE)
                        print("🔓 Switched to Read-Write mode")
                    elif mode_str == 'smart':
                        self.agent.set_mode(AgentMode.INTELLIGENT)
                        print("🧠 Switched to Intelligent mode")
                    else:
                        print("❌ Invalid mode. Use: ro, rw, or smart")
                
                else:
                    self.execute_task(task)
                    
            except KeyboardInterrupt:
                print("\n⏹️ Interrupted")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def run(self, args):
        """Main execution flow"""
        print("🚀 SSH Agent CLI")
        print("================")
        
        try:
            # Connect to server
            if not self.connect_to_server(args):
                return 1
            
            # Execute specific task if provided
            if args.task:
                self.execute_task(args.task, args.auto_approve)
            else:
                # Run interactive session
                self.interactive_session()
            
            return 0
            
        except KeyboardInterrupt:
            print("\n⏹️ Interrupted by user")
            return 1
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return 1
        finally:
            if self.agent:
                self.agent.disconnect()
                print("👋 Disconnected")

def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Interactive SSH Agent with LLM capabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Interactive mode
  %(prog)s -H localhost -u testuser --password -t "check disk space"
  %(prog)s -H 192.168.1.100 -u admin -k ~/.ssh/id_rsa -m smart -t "install nginx"
  %(prog)s -H server.com -u root -p 2222 --password -m rw -t "restart apache"
  %(prog)s -H localhost -u testuser --password --auto-approve -t "update system"
  
Environment Variables:
  OPENAI_API_KEY      # For OpenAI LLM features
  ANTHROPIC_API_KEY   # For Anthropic LLM features
        """
    )
    
    parser.add_argument(
        "-t", "--task",
        help="Specific task to execute (otherwise interactive mode)"
    )
    
    parser.add_argument(
        "-H", "--hostname",
        help="Server hostname or IP address"
    )
    
    parser.add_argument(
        "-u", "--username",
        help="SSH username"
    )
    
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=22,
        help="SSH port (default: 22)"
    )
    
    parser.add_argument(
        "-k", "--key",
        help="Path to SSH private key file"
    )
    
    parser.add_argument(
        "--password",
        action="store_true",
        help="Use password authentication (will prompt for password)"
    )
    
    parser.add_argument(
        "-m", "--mode",
        choices=["ro", "rw", "smart"],
        default="ro",
        help="Agent mode: ro (read-only), rw (read-write), smart (intelligent) (default: ro)"
    )
    
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Auto-approve all steps in intelligent mode"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    cli = SSHAgentCLI()
    return cli.run(args)

if __name__ == "__main__":
    sys.exit(main())
