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
        elif os.getenv("OPENROUTER_API_KEY"):
            llm_provider = LLMProvider.OPENROUTER
            llm_api_key = os.getenv("OPENROUTER_API_KEY")
            print("🤖 Using OpenRouter for LLM features")
        elif os.getenv("ANTHROPIC_API_KEY"):
            llm_provider = LLMProvider.ANTHROPIC
            llm_api_key = os.getenv("ANTHROPIC_API_KEY")
            print("🤖 Using Anthropic for LLM features")
        elif mode == AgentMode.INTELLIGENT:
            print("⚠️ Warning: No LLM API key found. Set OPENAI_API_KEY, OPENROUTER_API_KEY, or ANTHROPIC_API_KEY for full intelligent features.")
            print("🔄 Falling back to OpenAI provider (will fail without API key)")
            llm_provider = LLMProvider.OPENAI
        
        # Create agent with detected LLM provider
        self.agent = SSHAgent(hostname, username, mode, port, llm_provider, llm_api_key)
        
        print(f"\n🔌 Connecting to {username}@{hostname}:{port}...")
        
        # Determine connection method
        if args and hasattr(args, 'key') and args.key:
            # Use specified SSH key (assume no passphrase for CLI usage)
            key_path = Path(args.key).expanduser()
            if not key_path.exists():
                print(f"❌ SSH key not found: {key_path}")
                return False
            
            success = self.agent.connect_with_key(key_path, None)
            
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
                    # Check if exit code was interpreted
                    validation_info = getattr(cmd_result, 'validation_info', {})
                    exit_interpretation = validation_info.get('exit_interpretation', {})
                    treated_as_success = validation_info.get('treated_as_success', False)
                    
                    if treated_as_success:
                        status = "ℹ️"  # Informational
                        print(f"  {i}. {status} {cmd_result.command} (exit: {cmd_result.exit_code})")
                        print(f"     Info: {exit_interpretation.get('message', 'Informational exit code')}")
                    elif cmd_result.exit_code == 0:
                        status = "✅"
                        print(f"  {i}. {status} {cmd_result.command}")
                    else:
                        status = "❌"
                        print(f"  {i}. {status} {cmd_result.command} (exit: {cmd_result.exit_code})")
                        if cmd_result.stderr:
                            print(f"     Error: {cmd_result.stderr[:100]}...")
                    
                    # Show auto-generated values if any
                    if hasattr(cmd_result, 'validation_info') and cmd_result.validation_info:
                        generated_values = cmd_result.validation_info.get('generated_values', {})
                        if generated_values:
                            print(f"     🔧 Auto-generated: {', '.join(generated_values.keys())}")
                        
                        generated_command = cmd_result.validation_info.get('generated_command', '')
                        if generated_command and generated_command != cmd_result.command:
                            print(f"     🔄 Corrected to: {generated_command}")
            
            # Show skipped steps if any
            if hasattr(result, 'skipped_steps') and result.skipped_steps:
                print("\n⏭️ Skipped Steps (already completed):")
                for skip in result.skipped_steps:
                    print(f"  {skip['step']}. ✅ {skip['description']}")
                    print(f"     Reason: {skip['reason']}")
            
            # Show auto-generation summary
            auto_generated_items = []
            for cmd_result in result.results:
                if hasattr(cmd_result, 'validation_info'):
                    generated_values = cmd_result.validation_info.get('generated_values', {})
                    auto_generated_items.extend(generated_values.keys())
            
            if auto_generated_items:
                print(f"\n🎲 Auto-generated: {', '.join(set(auto_generated_items))}")
        
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
        print("Commands: 'health', 'context', 'mode <ro|rw|smart>', 'cache-status', 'cache-clear', 'quit'")
        
        while True:
            try:
                task = input("\n💬 Enter task/command: ").strip()
                
                if not task:
                    continue
                
                if task.lower() in ['quit', 'exit', 'q']:
                    break
                
                elif task.lower() == 'health':
                    if not (os.getenv("OPENAI_API_KEY") or os.getenv("OPENROUTER_API_KEY") or os.getenv("ANTHROPIC_API_KEY")):
                        print("❌ Health analysis requires an LLM API key (OPENAI_API_KEY, OPENROUTER_API_KEY, or ANTHROPIC_API_KEY)")
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
                
                elif task.lower() == 'cache-status':
                    if not (os.getenv("OPENAI_API_KEY") or os.getenv("OPENROUTER_API_KEY") or os.getenv("ANTHROPIC_API_KEY")):
                        print("❌ Cache status check requires an LLM API key (OPENAI_API_KEY, OPENROUTER_API_KEY, or ANTHROPIC_API_KEY)")
                        continue
                    
                    try:
                        from datetime import datetime
                        # Check cache status on remote server
                        cache_file = "/tmp/ssh_agent_env_cache.json"
                        check_result = self.agent.execute_command(f"test -f {cache_file} && stat -c '%Y %s' {cache_file} || echo 'missing'")
                        
                        if check_result.allowed and check_result.exit_code == 0:
                            if "missing" in check_result.stdout:
                                print("📦 Environment Cache Status: Not found")
                            else:
                                try:
                                    timestamp_str, size_str = check_result.stdout.strip().split()
                                    cache_timestamp = int(timestamp_str)
                                    cache_size = int(size_str)
                                    current_time = int(datetime.now().timestamp())
                                    age_minutes = (current_time - cache_timestamp) / 60
                                    
                                    print(f"📦 Environment Cache Status:")
                                    print(f"   📅 Age: {age_minutes:.1f} minutes")
                                    print(f"   📏 Size: {cache_size} bytes")
                                    print(f"   📍 Location: {cache_file}")
                                    
                                    if age_minutes > 30:
                                        print(f"   ⚠️  Cache is old (>30 minutes)")
                                    else:
                                        print(f"   ✅ Cache is fresh")
                                        
                                except (ValueError, IndexError):
                                    print("📦 Environment Cache Status: Found but invalid format")
                        else:
                            print(f"❌ Could not check cache status: {check_result.stderr}")
                            
                    except Exception as e:
                        print(f"❌ Error checking cache status: {e}")

                elif task.lower() == 'cache-clear':
                    try:
                        result = self.agent.execute_command("rm -f /tmp/ssh_agent_env_cache.json")
                        if result.allowed and result.exit_code == 0:
                            print("🗑️ Environment cache cleared from remote server")
                        else:
                            print(f"❌ Failed to clear cache: {result.stderr}")
                    except Exception as e:
                        print(f"❌ Error clearing cache: {e}")
                
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
                logger.error(f"Task execution failed: {e}")
                logger.exception("Full traceback:")
                print(f"❌ Unexpected error: {e}")
                print(f"📍 Error type: {type(e).__name__}")
                print(f"📄 Check logs for full details")
                
                # Try to provide more context
                if hasattr(e, '__cause__') and e.__cause__:
                    print(f"🔗 Caused by: {e.__cause__}")
                
                # If it's a specific type of error, provide guidance
                if "NoneType" in str(e):
                    print("💡 This appears to be a data structure issue. The agent may have received unexpected data.")
                    print("   Try running the command again or check your connection.")
                elif "JSON" in str(e):
                    print("💡 This appears to be a response parsing issue. The LLM may have returned malformed data.")
                    print("   Try running the command again or check your API key.")
                elif "connection" in str(e).lower():
                    print("💡 This appears to be a connection issue. Check your network and SSH connection.")
    
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
  OPENROUTER_API_KEY  # For OpenRouter LLM features (access to multiple models)
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
