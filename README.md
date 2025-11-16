# SSH Agent - Intelligent Remote Server Management

An intelligent SSH agent that combines traditional command execution with LLM-powered analysis and planning for safe, efficient server management.

## ⚠️ Important Safety Notice

**This tool can execute commands on remote servers. Always:**
- Start with READ-ONLY mode to understand the system
- Review all planned actions before execution
- Test on non-production systems first
- Keep backups of critical data
- Use the enhanced executor for critical operations (includes rollback capabilities)

## Features

### 🔒 Safety-First Design
- **Mode-based restrictions**: Read-only, read-write, and intelligent modes
- **Command validation**: Blocks dangerous operations in read-only mode
- **LLM safety analysis**: AI validates action plans before execution
- **System snapshots**: Automatic backup points for rollback
- **Human escalation**: Requires human approval for risky operations

### 🧠 Intelligent Operations
- **Goal-based execution**: Describe what you want, let AI plan the steps
- **Context awareness**: Maintains understanding of server state
- **Retry logic**: Automatically retries failed operations with AI guidance
- **Health analysis**: AI-powered system health assessment
- **Smart troubleshooting**: Diagnose and resolve issues intelligently

### 🛠 Multiple Execution Modes
1. **Basic Executor**: Direct command execution with safety checks
2. **Smart Executor**: LLM-planned multi-step operations
3. **Enhanced Executor**: Full safeguards, retries, and human escalation

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

# Connect with SSH key
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m ro

# Execute specific task
python ssh_agent_cli.py -H localhost -u user --password -t "check disk space"

# Intelligent mode with auto-approval (use carefully!)
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -m smart -t "install nginx" --auto-approve
```

### Python API Usage

```python
from ssh_agent import SSHAgent, AgentMode, LLMProvider

# Create agent
agent = SSHAgent(
    hostname="your-server.com",
    username="admin",
    mode=AgentMode.READ_ONLY,  # Start safe!
    llm_provider=LLMProvider.OPENAI
)

# Connect
if agent.connect_with_key("~/.ssh/id_rsa"):
    # Basic command execution
    result = agent.execute_command("df -h")
    print(result.stdout)
    
    # Intelligent task execution
    agent.set_mode(AgentMode.INTELLIGENT)
    task_result = agent.execute_smart_action("install and configure nginx")
    
    # Enhanced execution with safeguards
    enhanced_result = agent.execute_enhanced_task(
        "update all packages and restart services",
        auto_approve=False  # Will prompt for approval
    )
    
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
- **Purpose**: AI-guided operations
- **Features**: LLM planning, safety validation, context awareness
- **Safeguards**: AI reviews all actions, suggests safer alternatives
- **Use for**: Complex tasks, learning, guided administration

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

## Enhanced Execution Flow

The enhanced executor provides the most robust execution with:

1. **Goal Understanding**: AI analyzes and breaks down your request
2. **Prerequisite Collection**: Gathers system state and dependencies
3. **Safeguard Creation**: Takes system snapshots for rollback
4. **Plan Refinement**: AI creates detailed, safe action plans
5. **Execution with Retries**: Up to 3 attempts with AI consultation
6. **Human Escalation**: Involves human after failures
7. **Success Verification**: Confirms goal achievement
8. **Rollback Capability**: Restores system if needed

```python
# Human callback for escalation
def human_callback(goal, failed_attempts, prerequisites):
    print(f"Task failed: {goal}")
    print(f"Attempts: {len(failed_attempts)}")
    
    decision = input("Continue with human guidance? (y/n): ")
    if decision.lower() == 'y':
        guidance = input("Provide guidance: ")
        return {"continue": True, "guidance": guidance}
    return {"continue": False}

# Execute with full safeguards
result = agent.execute_enhanced_task(
    "migrate database to new server",
    auto_approve=False,
    human_callback=human_callback
)
```

## Best Practices

### 🚦 Start Safe
1. **Always begin in READ-ONLY mode**
2. **Understand the system first** using health analysis
3. **Test on non-production systems**
4. **Review AI-generated plans** before execution

### 🔍 Monitor and Verify
```python
# Check system health
analysis = agent.analyze_server_health()
print(f"Health: {analysis.summary}")
print(f"Issues: {analysis.issues}")

# Get context summary
print(agent.get_context_summary())
```

### 🛡️ Use Safeguards
```python
# For critical operations, use enhanced executor
result = agent.execute_enhanced_task(
    "update kernel and reboot",
    auto_approve=False,  # Always review critical changes
    human_callback=your_callback_function
)

# Check if rollback was needed
if result.rollback_performed:
    print("Operation was rolled back due to issues")
```

### 📝 Review Before Execution
```python
# Get action plan without executing
current_state = agent.context.get_current_state()
plan = agent.analyzer.suggest_actions("install docker", current_state)

print("Planned steps:")
for i, step in enumerate(plan.steps, 1):
    print(f"{i}. {step.get('description', step)}")
    print(f"   Command: {step.get('command', step)}")

# Validate plan safety
validation = agent.analyzer.validate_action_plan(
    [step.get('command', step) for step in plan.steps],
    current_state
)
print(f"Plan safety: {validation}")
```

## Common Use Cases

### System Monitoring
```bash
# Health check
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -t "health"

# Context summary
python ssh_agent_cli.py -H server.com -u admin -k ~/.ssh/id_rsa -t "context"
```

### Package Management
```python
# Smart package installation
result = agent.execute_smart_action("install docker and docker-compose")

# Or use specific package management
pkg_result = agent.manage_packages(["nginx", "certbot"], "install")
```

### Service Management
```python
# Intelligent service management
svc_result = agent.manage_service("nginx", "restart")
print(f"Service {svc_result.service_name}: {svc_result.current_state}")
```

### Troubleshooting
```python
# AI-powered diagnosis
diagnosis = agent.diagnose_issue("website is slow")
print(f"Suggested actions: {diagnosis['action_plan'].steps}")
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
# Verify API key
echo $OPENAI_API_KEY

# Test API connectivity
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     https://api.openai.com/v1/models
```

### Permission Issues
```bash
# Check user permissions
id

# Check sudo access
sudo -l
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

[Add your license here]

## Disclaimer

This tool executes commands on remote servers. Users are responsible for:
- Understanding the commands being executed
- Testing on non-production systems
- Maintaining proper backups
- Following security best practices
- Complying with organizational policies

The authors are not responsible for any damage caused by misuse of this tool.
