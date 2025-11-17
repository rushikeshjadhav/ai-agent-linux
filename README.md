# SSH Agent - Intelligent Remote Server Management

An intelligent SSH agent that combines traditional command execution with LLM-powered analysis and planning for safe, efficient server management.

## ⚠️ Important Safety Notice

**This tool can execute commands on remote servers. Always:**
- Start with READ-ONLY mode to understand the system
- Review all planned actions before execution
- Test on non-production systems first
- Keep backups of critical data
- Use intelligent mode for complex operations with AI guidance

## Features

### 🔒 Safety-First Design
- **Mode-based restrictions**: Read-only, read-write, and intelligent modes
- **Command validation**: Blocks dangerous operations in read-only mode
- **LLM safety analysis**: AI validates action plans before execution
- **Container awareness**: Automatically adapts to container environments
- **Auto-approval controls**: Human oversight for critical operations

### 🧠 Intelligent Operations
- **Goal-based execution**: Describe what you want, let AI plan the steps
- **Context awareness**: Maintains understanding of server state
- **Advanced failure recovery**: Automatic replanning when operations fail
- **Health analysis**: AI-powered system health assessment
- **Smart troubleshooting**: Diagnose and resolve issues intelligently

### 🐳 Container Environment Support
- **Automatic detection**: Identifies Docker, LXC, and other container types
- **Smart adaptations**: Uses container-appropriate alternatives for system commands
- **Capability assessment**: Determines what operations are possible in containers
- **Alternative suggestions**: Provides workarounds for container limitations

### 🔄 Advanced Failure Recovery
- **Automatic replanning**: When critical steps fail, AI creates new approaches
- **Failure analysis**: LLM analyzes why commands failed and suggests fixes
- **Multiple recovery strategies**: Handles missing packages, permissions, container issues
- **Context-aware recovery**: Uses system state to inform recovery decisions

### 🎲 Automatic Value Generation
- **Secure passwords**: Auto-generates strong passwords for user creation
- **Timestamps**: Adds timestamps to backup files and logs
- **Random strings**: Creates unique identifiers and temporary files
- **Placeholder system**: Handles commands requiring user input automatically

### ⚡ Performance Optimizations
- **Environment caching**: Caches system information for 30 minutes
- **Remote storage**: Cache stored on target server, survives disconnections
- **Smart invalidation**: Clears cache when system-changing operations occur
- **Prerequisite optimization**: Skips unnecessary steps based on system state

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd ssh-agent

# Install dependencies
pip install -r requirements.txt

# Set up API keys (choose one)
export OPENAI_API_KEY="your-openai-key"
export OPENROUTER_API_KEY="your-openrouter-key"  # Access to multiple models
export ANTHROPIC_API_KEY="your-anthropic-key"
```

## Quick Start

### Command Line Usage

```bash
# Interactive mode (safest - prompts for everything)
python ssh_agent_cli.py

# Connect with SSH key in read-only mode
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m ro

# Execute specific task with password auth
python ssh_agent_cli.py -H localhost -u user --password -t "check disk space"

# Intelligent mode with auto-approval (use carefully!)
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m smart -t "install nginx" --auto-approve

# Container operations (automatically detected)
python ssh_agent_cli.py -H container.local -u user -k ~/.ssh/id_rsa -m smart -t "start web service"

# Complex task with auto-generation
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m smart -t "create backup user with secure password"
```

### Interactive Commands

```bash
# Available commands in interactive mode:
health          # AI-powered health analysis (requires LLM API key)
context         # Show current server context and command history
cache-status    # Check environment cache status and age
cache-clear     # Clear environment cache from remote server
mode <ro|rw|smart>  # Switch agent mode
quit            # Exit (also: exit, q)
```

### Python API Usage

```python
from ssh_agent import SSHAgent, AgentMode, LLMProvider

# Create agent with LLM provider
agent = SSHAgent(
    hostname="your-server.com",
    username="admin",
    mode=AgentMode.READ_ONLY,  # Start safe!
    llm_provider=LLMProvider.OPENAI,
    api_key="your-api-key"  # or set environment variable
)

# Connect
if agent.connect_with_key("~/.ssh/id_rsa"):
    # Basic command execution
    result = agent.execute_command("df -h")
    print(result.stdout)
    
    # Intelligent task execution with auto-generation
    agent.set_mode(AgentMode.INTELLIGENT)
    task_result = agent.execute_smart_action(
        "create user with secure password and ssh access",
        auto_approve=False  # Will prompt for approval
    )
    
    # Check execution results
    print(f"Success: {task_result.success}")
    print(f"Steps completed: {task_result.steps_completed}/{task_result.total_steps}")
    
    # Check auto-generated values
    for cmd_result in task_result.results:
        if hasattr(cmd_result, 'validation_info'):
            generated = cmd_result.validation_info.get('generated_values', {})
            if generated:
                print(f"Auto-generated: {list(generated.keys())}")
    
    # Health analysis (requires LLM)
    health = agent.analyze_server_health()
    print(f"Health: {health.summary}")
    print(f"Issues: {health.issues}")
    
    agent.disconnect()
```

## Agent Modes

### 🔒 Read-Only Mode (`ro`)
- **Purpose**: Safe exploration and monitoring
- **Allowed**: System information, file reading, process listing
- **Blocked**: File modifications, service changes, package operations
- **Use for**: Initial assessment, monitoring, troubleshooting

### 🔓 Read-Write Mode (`rw`)
- **Purpose**: Full system access
- **Allowed**: All commands (use with extreme caution)
- **Blocked**: Nothing (relies on user judgment)
- **Use for**: Experienced administrators, emergency situations

### 🧠 Intelligent Mode (`smart`)
- **Purpose**: AI-guided operations with advanced features
- **Features**: 
  - LLM planning with prerequisite collection
  - Automatic failure recovery and replanning
  - Container environment adaptation
  - Auto-generation of secure values
  - Environment caching for performance
- **Safeguards**: AI reviews all actions, suggests safer alternatives
- **Use for**: Complex tasks, learning, guided administration, container management

## LLM Providers

### OpenAI (GPT-4)
```bash
export OPENAI_API_KEY="sk-..."
```
- **Best for**: General system administration
- **Models**: GPT-4, GPT-3.5-turbo
- **Strengths**: Broad knowledge, reliable responses

### OpenRouter (Multiple Models)
```bash
export OPENROUTER_API_KEY="sk-or-..."
```
- **Best for**: Access to multiple AI models
- **Models**: Claude 3.5 Sonnet, GPT-4, Llama, and more
- **Strengths**: Model variety, competitive pricing

### Anthropic (Claude)
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```
- **Best for**: Safety-conscious operations
- **Models**: Claude 3 Sonnet, Claude 3 Haiku
- **Strengths**: Safety focus, detailed explanations

## Intelligent Execution Flow

The intelligent mode provides sophisticated execution with:

1. **Environment Analysis**: Comprehensive system detection and caching
2. **Prerequisite Collection**: AI determines what info to gather before planning
3. **Informed Planning**: Creates action plans based on actual system state
4. **Container Adaptation**: Automatically adjusts for container environments
5. **Auto-Generation**: Fills in missing values (passwords, timestamps, etc.)
6. **Failure Recovery**: Automatic replanning when critical steps fail
7. **Success Verification**: Confirms goal achievement with smart exit code interpretation

```python
# Execute intelligent task with auto-generation
result = agent.execute_smart_action(
    "create user with secure password and configure ssh access",
    auto_approve=False  # Will prompt for approval of each step
)

# Check what was auto-generated
for cmd_result in result.results:
    if hasattr(cmd_result, 'validation_info'):
        generated = cmd_result.validation_info.get('generated_values', {})
        if generated:
            print(f"Auto-generated: {list(generated.keys())}")
```

## Container Environment Handling

### Automatic Detection and Adaptation

```python
# Agent automatically detects container environment
agent = SSHAgent("container-host", "user", AgentMode.INTELLIGENT)
agent.connect_with_key("~/.ssh/id_rsa")

# This task automatically adapts for containers
result = agent.execute_smart_action("start web service")

# In containers, this becomes:
# systemctl start nginx → nginx -g "daemon off;" &
# firewall-cmd → echo "Configure firewall on container host"
```

### Container Limitations Handled
- **No systemd**: Uses direct process execution or alternatives
- **No iptables**: Suggests application-level security configuration
- **Limited kernel access**: Avoids kernel module operations
- **No init system**: Uses process managers like supervisord

## Advanced Failure Recovery

### Automatic Replanning Example

```python
# If initial approach fails, agent automatically replans
result = agent.execute_smart_action("install minio object storage")

# Original plan: dnf install minio (fails - package not found)
# Agent detects critical failure and replans:
# 1. Try alternative repositories
# 2. Download and install manually
# 3. Use Docker container instead
# 4. Find alternative object storage solutions
```

### Failure Types Handled
- **Command not found**: Attempts package installation, finds alternatives
- **Permission denied**: Adds sudo or suggests alternative approaches  
- **Package unavailable**: Finds alternative packages or installation methods
- **Container incompatibility**: Provides container-appropriate alternatives
- **Service failures**: Uses alternative service management approaches

## Automatic Value Generation

### Supported Auto-Generation Types

```python
# Commands with placeholders are automatically filled
result = agent.execute_smart_action("create backup user with secure access")

# Original command: "useradd backup && echo 'backup:<password>' | chpasswd"
# Becomes: "useradd backup && echo 'backup:Kx9#mP2$vL8@nQ4!' | chpasswd"

# Backup with timestamp: "tar -czf backup_<timestamp>.tar.gz /data"
# Becomes: "tar -czf backup_20241116_143022.tar.gz /data"
```

### Generation Types
- **Passwords**: 16-character secure passwords with mixed case, numbers, symbols
- **Timestamps**: YYYYMMDD_HHMMSS format for unique file naming
- **Random strings**: Alphanumeric strings for identifiers
- **Temporary files**: Unique temporary filenames
- **Secure keys**: Cryptographic key identifiers
- **Random ports**: Available port numbers in safe ranges

## Performance Features

### Environment Caching

```python
# First run: Comprehensive environment detection (~30 seconds)
agent.execute_smart_action("install docker")

# Subsequent runs: Uses cached environment info (~5 seconds)
agent.execute_smart_action("configure docker networking")

# Cache automatically invalidates for system-changing operations
agent.execute_smart_action("update all packages")  # Clears cache
```

### Cache Management

```bash
# Check cache status
cache-status

# Clear cache manually
cache-clear

# Cache is stored on remote server at /tmp/ssh_agent_env_cache.json
# TTL: 30 minutes
# Survives SSH disconnections
```

## Best Practices

### 🚦 Start Safe
1. **Always begin in READ-ONLY mode**
2. **Understand the system first** using health analysis
3. **Test on non-production systems**
4. **Review AI-generated plans** before execution

### 🔍 Monitor and Verify
```python
# Check system health (requires LLM API key)
analysis = agent.analyze_server_health()
print(f"Health: {analysis.summary}")
print(f"Issues: {analysis.issues}")
print(f"Recommendations: {analysis.recommendations}")

# Get context summary
print(agent.get_context_summary())

# Check environment cache status
cache_result = agent.execute_command("test -f /tmp/ssh_agent_env_cache.json && echo 'cached' || echo 'no cache'")
print(f"Cache status: {cache_result.stdout}")
```

### 🛡️ Use Intelligent Mode Safeguards
```python
# For critical operations, use intelligent mode with manual approval
result = agent.execute_smart_action(
    "update all packages and restart services",
    auto_approve=False  # Will prompt for approval of each step
)

# Check execution details
print(f"Task: {result.task_description}")
print(f"Success: {result.success}")
print(f"Steps: {result.steps_completed}/{result.total_steps}")

# Check for auto-generated values
auto_generated_items = []
for cmd_result in result.results:
    if cmd_result and hasattr(cmd_result, 'validation_info'):
        validation_info = getattr(cmd_result, 'validation_info', {}) or {}
        generated_values = validation_info.get('generated_values', {})
        auto_generated_items.extend(generated_values.keys())

if auto_generated_items:
    print(f"Auto-generated: {', '.join(set(auto_generated_items))}")
```

### 📝 Review Before Execution
```python
# Get action plan without executing (requires LLM)
current_state = agent.context.get_current_state()
plan = agent.analyzer.suggest_actions("install docker", current_state)

print("Planned steps:")
for i, step in enumerate(plan.steps, 1):
    if isinstance(step, dict):
        print(f"{i}. {step.get('description', 'No description')}")
        print(f"   Command: {step.get('command', 'No command')}")
    else:
        print(f"{i}. {step}")

# Validate plan safety
commands = [step.get('command', step) if isinstance(step, dict) else str(step) for step in plan.steps]
validation = agent.analyzer.validate_action_plan(commands, current_state)
print(f"Plan safety: {validation.get('safe', False)}")
print(f"Reason: {validation.get('reason', 'No reason provided')}")
```

## Common Use Cases

### System Monitoring
```bash
# Health check (requires LLM API key)
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m smart -t "health"

# Context summary
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m smart -t "context"

# Cache status check
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m smart -t "cache-status"
```

### Package Management with Auto-Generation
```python
# Smart package installation with automatic adaptation
result = agent.execute_smart_action("install docker and configure it for production use")

# The agent will:
# 1. Detect the OS and use appropriate package manager
# 2. Handle container environments appropriately
# 3. Auto-generate any needed configuration values
# 4. Adapt commands for the specific environment

print(f"Installation success: {result.success}")
for cmd_result in result.results:
    if hasattr(cmd_result, 'validation_info'):
        generated = cmd_result.validation_info.get('generated_values', {})
        if generated:
            print(f"Auto-generated: {list(generated.keys())}")
```

### Service Management with Container Awareness
```python
# Intelligent service management that adapts to environment
result = agent.execute_smart_action("start nginx web server")

# In regular systems: systemctl start nginx
# In containers: nginx -g "daemon off;" &
# Agent automatically chooses the right approach

print(f"Service management success: {result.success}")
```

### Container Operations
```python
# Agent automatically detects and adapts to container environments
result = agent.execute_smart_action("configure firewall for web traffic")

# In regular systems: Uses iptables/firewall-cmd
# In containers: Suggests host-level configuration
# Provides appropriate alternatives automatically

if result.skipped_steps:
    print("Container adaptations made:")
    for skip in result.skipped_steps:
        print(f"  - {skip['description']}: {skip['reason']}")
```

### Advanced Failure Recovery
```python
# Complex task with automatic replanning on failure
result = agent.execute_smart_action("install and configure minio object storage")

# If initial approach fails (e.g., package not found):
# 1. Agent detects critical failure
# 2. Analyzes why it failed
# 3. Creates new plan (try different repos, manual install, alternatives)
# 4. Executes recovery plan automatically

print(f"Recovery attempts: {result.recovery_attempts}")
if result.failure_contexts:
    for failure in result.failure_contexts:
        print(f"Failure {failure.attempt_number}: {failure.original_error}")
        print(f"Recovery: {failure.llm_analysis}")
```

## Security Considerations

### 🔐 Authentication
- **SSH Keys**: Preferred method, supports passphrases
- **Password Auth**: Available but less secure
- **Key Management**: Store keys securely, use proper permissions

### 🛡️ Access Control
- **Principle of Least Privilege**: Start with read-only mode
- **Command Validation**: Built-in safety checks
- **Audit Trail**: All commands are logged with context

### 🔍 Monitoring
- **Command History**: Track all executed commands
- **System Snapshots**: Monitor system state changes
- **LLM Analysis**: AI reviews all operations for safety

## Troubleshooting

### Connection Issues
```bash
# Test basic connectivity
ssh user@hostname

# Check SSH key permissions
chmod 600 ~/.ssh/id_rsa

# Verify SSH agent
ssh-add -l
```

### LLM Issues
```bash
# Verify API key (choose your provider)
echo $OPENAI_API_KEY
echo $OPENROUTER_API_KEY
echo $ANTHROPIC_API_KEY

# Test OpenAI API connectivity
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     https://api.openai.com/v1/models

# Test OpenRouter API connectivity
curl -H "Authorization: Bearer $OPENROUTER_API_KEY" \
     https://openrouter.ai/api/v1/models

# Test Anthropic API connectivity
curl -H "x-api-key: $ANTHROPIC_API_KEY" \
     https://api.anthropic.com/v1/messages
```

### Container Environment Issues
```bash
# Check if running in container
cat /.dockerenv 2>/dev/null && echo "Docker container" || echo "Not Docker"

# Check container capabilities
systemctl --version 2>/dev/null && echo "systemd available" || echo "No systemd"

# Check for container limitations
cat /proc/1/cgroup | grep -E "(docker|lxc|containerd)" && echo "Container detected"
```

### Cache Issues
```bash
# Check cache status on remote server
ssh user@host "test -f /tmp/ssh_agent_env_cache.json && stat -c '%Y %s' /tmp/ssh_agent_env_cache.json || echo 'No cache'"

# Clear cache manually
ssh user@host "rm -f /tmp/ssh_agent_env_cache.json"

# Check cache age (in interactive mode)
cache-status
```

### Auto-Generation Issues
```python
# If auto-generation fails, check the command structure
result = agent.execute_smart_action("create user with password")

# Look for validation info in results
for cmd_result in result.results:
    if hasattr(cmd_result, 'validation_info'):
        validation_info = cmd_result.validation_info
        if 'generated_command' in validation_info:
            print(f"Original: {cmd_result.command}")
            print(f"Generated: {validation_info['generated_command']}")
            print(f"Values: {validation_info.get('generated_values', {})}")
```

### Permission Issues
```bash
# Check user permissions
id

# Check sudo access
sudo -l

# For container environments, check capabilities
capsh --print 2>/dev/null || echo "No capability info available"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Dependencies

This project uses several third-party libraries, each with their own licenses:
- **paramiko**: LGPL 2.1+ (SSH functionality)
- **openai**: MIT License (OpenAI API client)
- **anthropic**: MIT License (Anthropic API client)
- **httpx**: BSD 3-Clause (HTTP client)
- **jsonschema**: MIT License (JSON validation)

Please review the licenses of these dependencies to ensure compliance with your use case.

## Disclaimer

This tool executes commands on remote servers and can automatically generate values like passwords. Users are responsible for:
- Understanding the commands being executed
- Testing on non-production systems first
- Maintaining proper backups before system changes
- Following security best practices
- Reviewing auto-generated values for security compliance
- Understanding container environment limitations
- Complying with organizational policies
- Monitoring cache files and generated credentials

The authors are not responsible for any damage caused by misuse of this tool. The automatic failure recovery and replanning features are designed to help but may not prevent all issues.

## Version Information

This README reflects the current codebase features including:
- Container environment detection and adaptation
- Advanced failure recovery with automatic replanning
- Prerequisite-informed planning
- Automatic value generation with placeholders
- Environment caching for performance
- Smart exit code interpretation
- LLM-powered failure analysis

For the most up-to-date feature list, check the source code in the `ssh_agent/` directory.
