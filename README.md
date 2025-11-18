# SSH Agent - Intelligent Remote Server Management

An intelligent SSH agent that combines traditional command execution with LLM-powered analysis and planning for safe, efficient server management with advanced container awareness and failure recovery.

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
- **Plan discussion**: Interactive plan review and modification before execution

### 🧠 Intelligent Operations
- **Goal-based execution**: Describe what you want, let AI plan the steps
- **Context awareness**: Maintains understanding of server state
- **Advanced failure recovery**: Automatic replanning when operations fail
- **Health analysis**: AI-powered system health assessment
- **Smart troubleshooting**: Diagnose and resolve issues intelligently
- **Interactive planning**: Review and modify AI-generated plans before execution

### 🐳 Container Environment Support
- **Automatic detection**: Identifies Docker, LXC, and other container types including Apple Silicon
- **Smart adaptations**: Uses container-appropriate alternatives for system commands
- **Capability assessment**: Determines what operations are possible in containers
- **Alternative suggestions**: Provides workarounds for container limitations
- **Apple Silicon detection**: Recognizes emulated x86_64 containers on Apple Silicon hosts

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

### 🛡️ Enhanced Execution Modes
- **Basic Execution**: Direct command execution with safety checks
- **Smart Execution**: LLM-planned operations with container awareness
- **Enhanced Execution**: Full safeguards with system snapshots and rollback capabilities

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

# Intelligent mode with plan discussion
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m smart -t "install nginx" --discuss-plan

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

# Plan discussion in interactive mode:
install docker --discuss-plan  # Review plan before execution
```

### Python API Usage

```python
from ssh_agent import SSHAgent, AgentMode, LLMProvider

# Create agent with LLM provider
agent = SSHAgent(
    hostname="your-server.com",
    username="admin",
    mode=AgentMode.READ_ONLY,  # Start safe!
    llm_provider=LLMProvider.OPENROUTER,  # Recommended
    api_key="your-api-key"  # or set environment variable
)

# Connect
if agent.connect_with_key("~/.ssh/id_rsa"):
    # Basic command execution
    result = agent.execute_command("df -h")
    print(result.stdout)
    
    # Intelligent task execution with plan discussion
    agent.set_mode(AgentMode.INTELLIGENT)
    task_result = agent.execute_smart_action(
        "create user with secure password and ssh access",
        auto_approve=False,  # Will prompt for approval
        discuss_plan=True    # Interactive plan review
    )
    
    # Enhanced execution with full safeguards
    enhanced_result = agent.execute_enhanced_task(
        "setup production web server with monitoring",
        auto_approve=False,
        human_callback=lambda goal, attempts, prereqs: {"continue": True, "guidance": "Use nginx instead of apache"}
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
  - Interactive plan discussion
- **Safeguards**: AI reviews all actions, suggests safer alternatives
- **Use for**: Complex tasks, learning, guided administration, container management

## Execution Modes

### Basic Execution
- Direct command execution with mode-based safety checks
- Suitable for simple, well-understood operations

### Smart Execution
- LLM-powered planning and execution
- Container environment adaptation
- Automatic failure recovery with replanning
- Auto-generation of missing values

### Enhanced Execution
- Full safeguards with system snapshots
- Multiple retry attempts with LLM guidance
- Automatic rollback capabilities
- Human escalation for complex failures

```python
# Enhanced execution example
result = agent.execute_enhanced_task(
    "migrate database to new server",
    auto_approve=False,
    human_callback=lambda goal, attempts, prereqs: {
        "continue": True,
        "guidance": "Use pg_dump instead of mysqldump"
    }
)

print(f"Total attempts: {result.total_attempts}")
print(f"Rollback performed: {result.rollback_performed}")
print(f"Human escalation: {result.human_escalation_required}")
```

## Plan Discussion Feature

### Interactive Plan Review

```python
# Enable plan discussion for complex operations
result = agent.execute_smart_action(
    "setup complete web server with SSL and monitoring",
    discuss_plan=True  # Enables interactive plan review
)

# The user will see:
# 📋 Action Plan for: setup complete web server with SSL and monitoring
# ⏱️  Estimated time: 15-20 minutes
# 🛡️  Safety score: 0.8/1.0
# 
# 📝 Planned Steps (8 total):
#    1. Update package lists
#       💻 apt update
#    2. Install nginx web server
#       💻 apt install -y nginx
#    ...
# 
# 🤔 Plan Review Options:
# 1. Execute plan as-is
# 2. Suggest modifications
# 3. Cancel execution
# 4. Show detailed step information
# 5. Show environment context
```

### Plan Modification

```bash
# User can request modifications:
💭 Describe your suggested modifications: Also install certbot for SSL certificates and configure basic monitoring with htop

🔄 Revising plan based on your suggestions...
📝 Plan Revision Notes:
   Added certbot installation step and basic monitoring setup with htop for system resource monitoring.
✅ Plan revised successfully!
```

### CLI Plan Discussion

```bash
# Use --discuss-plan flag for interactive review
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m smart -t "install docker" --discuss-plan

# Or in interactive mode
💬 Enter task/command: setup web server --discuss-plan
```

## LLM Providers

### OpenRouter (Recommended)
```bash
export OPENROUTER_API_KEY="sk-or-..."
```
- **Best for**: Access to multiple AI models including Claude 3.5 Sonnet
- **Models**: Claude 3.5 Sonnet (default), GPT-4, Llama, and more
- **Strengths**: Model variety, competitive pricing, high reliability
- **Default Model**: Claude 3.5 Sonnet via OpenRouter

### OpenAI (GPT-4)
```bash
export OPENAI_API_KEY="sk-..."
```
- **Best for**: General system administration
- **Models**: GPT-4, GPT-3.5-turbo
- **Strengths**: Broad knowledge, reliable responses

### Anthropic (Claude)
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```
- **Best for**: Safety-conscious operations
- **Models**: Claude 3 Sonnet, Claude 3 Haiku
- **Strengths**: Safety focus, detailed explanations

## Container Environment Support

### Advanced Container Detection

The SSH agent provides sophisticated container environment detection:

```python
# Automatic detection works for various scenarios
agent = SSHAgent("container.local", "user", mode=AgentMode.INTELLIGENT)
agent.connect_with_key("~/.ssh/id_rsa")

# Check detailed container detection
env_info = agent.context.get_current_state()
environment_type = env_info.get('environment_type', {})

print(f"Is container: {environment_type.get('is_container')}")
print(f"Container type: {environment_type.get('container_type')}")
print(f"Platform info: {environment_type.get('platform_info')}")
print(f"Limitations: {environment_type.get('limitations')}")
print(f"Capabilities: {environment_type.get('capabilities')}")
```

### Apple Silicon Container Detection

```python
# Detects Apple Silicon even in emulated x86_64 containers
platform_specific = environment_type.get('platform_specific', {})
if platform_specific.get('is_apple_silicon'):
    print(f"Apple Silicon detected!")
    print(f"Emulated x86: {platform_specific.get('emulated_x86')}")
    print(f"Evidence: {platform_specific.get('apple_silicon_indicators')}")
    print(f"Confidence: {platform_specific.get('detection_confidence')}")
```

### Container Adaptations

```python
# This automatically uses container-appropriate alternatives
result = agent.execute_smart_action("start nginx service")

# Regular system: systemctl start nginx
# Container without systemd: nginx -g "daemon off;" &
# Container with limited systemd: service nginx start

# Firewall operations adapt automatically
result = agent.execute_smart_action("configure firewall for web traffic")
# Regular system: iptables/firewall-cmd rules
# Container: "Configure firewall on container host" + networking guidance
```

### Container Limitations Handled
- **No systemd**: Uses direct process execution (nginx, apache2 -D FOREGROUND)
- **Limited systemd**: Uses service command instead of systemctl
- **No iptables**: Suggests application-level security and host configuration
- **Limited kernel access**: Avoids kernel module operations
- **No init system**: Uses process managers or direct execution
- **Network restrictions**: Uses container networking features and environment variables

## Intelligent Execution Flow

The intelligent mode provides sophisticated execution with:

1. **Environment Analysis**: Comprehensive system detection and caching
2. **Prerequisite Collection**: AI determines what info to gather before planning
3. **Informed Planning**: Creates action plans based on actual system state
4. **Plan Discussion** (optional): Interactive review and modification
5. **Container Adaptation**: Automatically adjusts for container environments
6. **Auto-Generation**: Fills in missing values (passwords, timestamps, etc.)
7. **Failure Recovery**: Automatic replanning when critical steps fail
8. **Success Verification**: Confirms goal achievement with smart exit code interpretation

```python
# Execute intelligent task with plan discussion
result = agent.execute_smart_action(
    "create user with secure password and configure ssh access",
    auto_approve=False,  # Will prompt for approval of each step
    discuss_plan=True    # Interactive plan review before execution
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
# 1. Analyzes why installation failed
# 2. Creates new approach (try alternative repos, manual install, Docker)
# 3. Executes recovery plan automatically
# 4. Continues with original goal

print(f"Recovery attempts: {result.recovery_attempts}")
if result.failure_contexts:
    for failure in result.failure_contexts:
        print(f"Failure {failure.attempt_number}: {failure.original_error}")
        print(f"Recovery analysis: {failure.llm_analysis}")
```

### Failure Types Handled
- **Command not found**: Attempts package installation, finds alternatives
- **Permission denied**: Adds sudo or suggests alternative approaches  
- **Package unavailable**: Finds alternative packages or installation methods
- **Container incompatibility**: Provides container-appropriate alternatives
- **Service failures**: Uses alternative service management approaches
- **systemd not functional**: Automatically switches to direct service commands

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
- **Random ports**: Available port numbers in safe ranges (50000-59999)

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
4. **Use plan discussion** for complex operations
5. **Review AI-generated plans** before execution

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

### 🛡️ Use Plan Discussion for Critical Operations
```python
# For critical operations, use plan discussion
result = agent.execute_smart_action(
    "update all packages and restart services",
    auto_approve=False,  # Manual approval required
    discuss_plan=True    # Interactive plan review
)

# User can:
# 1. Review each planned step
# 2. Request modifications
# 3. See detailed step information
# 4. Cancel if needed
# 5. Approve execution
```

### 📝 Review Auto-Generated Values
```python
# Check what values were automatically generated
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

### Complex Operations with Plan Discussion
```bash
# Review plan before execution
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m smart -t "setup complete LAMP stack" --discuss-plan

# Interactive modification example:
# 📋 Action Plan for: setup complete LAMP stack
# 🤔 Plan Review Options:
# 2. Suggest modifications
# 💭 Describe your suggested modifications: Use nginx instead of apache and add SSL certificates
# 🔄 Revising plan based on your suggestions...
# ✅ Plan revised successfully!
```

### Container Operations with Auto-Detection
```python
# Agent automatically detects and adapts to container environments
result = agent.execute_smart_action("start web server and configure firewall")

# Regular system:
# - systemctl start nginx
# - firewall-cmd --add-port=80/tcp

# Container environment:
# - nginx -g "daemon off;" &
# - echo "Configure port 80 in container networking"

if result.skipped_steps:
    print("Container adaptations made:")
    for skip in result.skipped_steps:
        print(f"  - {skip['description']}: {skip['reason']}")
```

### Enhanced Execution with Safeguards
```python
# Use enhanced execution for critical operations
result = agent.execute_enhanced_task(
    "migrate production database",
    auto_approve=False,
    human_callback=lambda goal, attempts, prereqs: {
        "continue": True,
        "guidance": "Create full backup before migration"
    }
)

print(f"Execution phases: {result.execution_phases}")
print(f"System snapshots: {len(result.snapshots)}")
print(f"Rollback available: {not result.rollback_performed}")
```

## Security Considerations

### 🔐 Authentication
- **SSH Keys**: Preferred method, supports passphrases
- **Password Auth**: Available but less secure
- **Key Management**: Store keys securely, use proper permissions

### 🛡️ Access Control
- **Principle of Least Privilege**: Start with read-only mode
- **Command Validation**: Built-in safety checks with container awareness
- **Audit Trail**: All commands logged with context and auto-generated values
- **Plan Review**: Interactive plan discussion for transparency

### 🔍 Monitoring
- **Command History**: Track all executed commands
- **System Snapshots**: Monitor system state changes (enhanced mode)
- **LLM Analysis**: AI reviews all operations for safety
- **Failure Recovery**: Automatic recovery attempts are logged

### 🐳 Container Security
- **Capability Assessment**: Understands container limitations
- **Host-Level Operations**: Suggests appropriate host configuration
- **Network Security**: Recommends container networking best practices
- **Auto-Generated Values**: Secure password generation for container users

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

# Test OpenRouter API connectivity (recommended)
curl -H "Authorization: Bearer $OPENROUTER_API_KEY" \
     https://openrouter.ai/api/v1/models
```

### Container Environment Issues
```bash
# Check container detection manually
python -c "
from ssh_agent import SSHAgent
agent = SSHAgent('container.local', 'user')
agent.connect_with_key('~/.ssh/id_rsa')
env = agent.smart_executor._collect_comprehensive_environment_info()
env_type = env['environment_type']
print('Container:', env_type['is_container'])
print('Type:', env_type['container_type'])
print('Limitations:', env_type['limitations'])
print('Capabilities:', env_type['capabilities'])
if 'platform_specific' in env_type:
    ps = env_type['platform_specific']
    print('Apple Silicon:', ps.get('is_apple_silicon', False))
    print('Evidence:', ps.get('apple_silicon_indicators', []))
"
```

### Plan Discussion Issues
```bash
# If plan discussion doesn't work, check LLM connectivity
python ssh_agent_cli.py -H server.com -u user -k ~/.ssh/id_rsa -m smart -t "test" --discuss-plan

# Enable debug logging
export SSH_AGENT_LOG_LEVEL=DEBUG
python ssh_agent_cli.py -H server.com -u user -k ~/.ssh/id_rsa -m smart -t "install nginx" --discuss-plan
```

### Replanning Issues
```bash
# Enable debug logging to see replanning process
export SSH_AGENT_LOG_LEVEL=DEBUG
python ssh_agent_cli.py -H server.com -u user -t "install missing-package"

# Check for critical failure detection
# Look for log messages like:
# "Critical installation failure detected"
# "Triggering immediate replanning"
# "Replanning successful: X new steps generated"
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
- Understanding container environment implications
- Reviewing AI-generated plans before execution
- Securing plan discussion sessions
- Complying with organizational policies
- Monitoring cache files and generated credentials

The authors are not responsible for any damage caused by misuse of this tool. The automatic failure recovery, replanning features, and plan discussion are designed to help but may not prevent all issues.

## Version Information

This README reflects the current codebase features including:
- Container environment detection and adaptation (including Apple Silicon)
- Advanced failure recovery with automatic replanning
- Prerequisite-informed planning
- Automatic value generation with placeholders
- Environment caching for performance
- Smart exit code interpretation
- LLM-powered failure analysis
- Interactive plan discussion and modification
- Enhanced execution mode with safeguards
- Sophisticated container capability assessment

For the most up-to-date feature list, check the source code in the `ssh_agent/` directory.
