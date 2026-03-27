"""
AUTARCH Tool System
Defines tools that the agent can use to interact with the environment
"""

import os
import subprocess
import json
from typing import Callable, Dict, List, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

from .banner import Colors


@dataclass
class ToolParameter:
    """Definition of a tool parameter."""
    name: str
    description: str
    type: str = "string"
    required: bool = True
    default: Any = None


@dataclass
class Tool:
    """Definition of an agent tool."""
    name: str
    description: str
    function: Callable
    parameters: List[ToolParameter] = field(default_factory=list)
    category: str = "general"

    def to_schema(self) -> Dict[str, Any]:
        """Convert tool to JSON schema for LLM."""
        properties = {}
        required = []

        for param in self.parameters:
            properties[param.name] = {
                "type": param.type,
                "description": param.description
            }
            if param.required:
                required.append(param.name)

        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the tool with given parameters.

        Returns:
            Dict with 'success' bool and 'result' or 'error' string.
        """
        try:
            result = self.function(**kwargs)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}


class ToolRegistry:
    """Registry for managing available tools."""

    def __init__(self):
        self._tools: Dict[str, Tool] = {}
        self._register_builtin_tools()

    def register(self, tool: Tool):
        """Register a tool."""
        self._tools[tool.name] = tool

    def unregister(self, name: str):
        """Unregister a tool by name."""
        if name in self._tools:
            del self._tools[name]

    def get(self, name: str) -> Optional[Tool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> List[Tool]:
        """List all registered tools."""
        return list(self._tools.values())

    def get_tools_schema(self) -> List[Dict[str, Any]]:
        """Get JSON schema for all tools."""
        return [tool.to_schema() for tool in self._tools.values()]

    def get_tools_prompt(self) -> str:
        """Generate a tools description for the LLM prompt."""
        lines = ["Available tools:"]
        for tool in self._tools.values():
            lines.append(f"\n## {tool.name}")
            lines.append(f"Description: {tool.description}")
            if tool.parameters:
                lines.append("Parameters:")
                for param in tool.parameters:
                    req = "(required)" if param.required else "(optional)"
                    lines.append(f"  - {param.name} [{param.type}] {req}: {param.description}")
        return "\n".join(lines)

    def execute(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Execute a tool by name.

        Args:
            tool_name: Name of the tool to execute.
            **kwargs: Parameters to pass to the tool.

        Returns:
            Dict with execution result.
        """
        tool = self.get(tool_name)
        if not tool:
            return {"success": False, "error": f"Tool '{tool_name}' not found"}
        return tool.execute(**kwargs)

    def _register_builtin_tools(self):
        """Register built-in tools."""

        # Shell command execution
        self.register(Tool(
            name="shell",
            description="Execute a shell command and return the output. Use for system operations, running scripts, or gathering system information.",
            function=self._tool_shell,
            parameters=[
                ToolParameter("command", "The shell command to execute", "string", True),
                ToolParameter("timeout", "Timeout in seconds (default 30)", "integer", False, 30),
            ],
            category="system"
        ))

        # Read file
        self.register(Tool(
            name="read_file",
            description="Read the contents of a file. Use to examine files, configs, or source code.",
            function=self._tool_read_file,
            parameters=[
                ToolParameter("path", "Path to the file to read", "string", True),
                ToolParameter("max_lines", "Maximum number of lines to read (default all)", "integer", False),
            ],
            category="filesystem"
        ))

        # Write file
        self.register(Tool(
            name="write_file",
            description="Write content to a file. Creates the file if it doesn't exist, overwrites if it does.",
            function=self._tool_write_file,
            parameters=[
                ToolParameter("path", "Path to the file to write", "string", True),
                ToolParameter("content", "Content to write to the file", "string", True),
            ],
            category="filesystem"
        ))

        # List directory
        self.register(Tool(
            name="list_dir",
            description="List contents of a directory. Use to explore filesystem structure.",
            function=self._tool_list_dir,
            parameters=[
                ToolParameter("path", "Path to the directory (default: current)", "string", False, "."),
                ToolParameter("show_hidden", "Include hidden files (default: false)", "boolean", False, False),
            ],
            category="filesystem"
        ))

        # Search files
        self.register(Tool(
            name="search_files",
            description="Search for files matching a pattern. Use to find specific files.",
            function=self._tool_search_files,
            parameters=[
                ToolParameter("pattern", "Glob pattern to match (e.g., '*.py', '**/*.txt')", "string", True),
                ToolParameter("path", "Starting directory (default: current)", "string", False, "."),
            ],
            category="filesystem"
        ))

        # Search in files (grep)
        self.register(Tool(
            name="search_content",
            description="Search for text content within files. Use to find specific code or text.",
            function=self._tool_search_content,
            parameters=[
                ToolParameter("pattern", "Text or regex pattern to search for", "string", True),
                ToolParameter("path", "File or directory to search in", "string", False, "."),
                ToolParameter("file_pattern", "Glob pattern for files to search (e.g., '*.py')", "string", False),
            ],
            category="filesystem"
        ))

        # Create module
        self.register(Tool(
            name="create_module",
            description="Create a new AUTARCH module. Writes a Python file to the modules/ directory that becomes available in the dashboard.",
            function=self._tool_create_module,
            parameters=[
                ToolParameter("name", "Module filename without .py extension (e.g., port_scanner)", "string", True),
                ToolParameter("category", "Module category: defense, offense, counter, analyze, osint, or simulate", "string", True),
                ToolParameter("code", "Complete Python source code for the module", "string", True),
            ],
            category="development"
        ))

        # Task complete
        self.register(Tool(
            name="task_complete",
            description="Mark the current task as complete. Use when you have fully accomplished the goal.",
            function=self._tool_task_complete,
            parameters=[
                ToolParameter("summary", "Summary of what was accomplished", "string", True),
            ],
            category="control"
        ))

        # Ask user
        self.register(Tool(
            name="ask_user",
            description="Ask the user a question when you need clarification or input.",
            function=self._tool_ask_user,
            parameters=[
                ToolParameter("question", "The question to ask the user", "string", True),
            ],
            category="interaction"
        ))

        # Metasploit tools
        self.register(Tool(
            name="msf_connect",
            description="Connect to Metasploit RPC. Required before using other MSF tools.",
            function=self._tool_msf_connect,
            parameters=[
                ToolParameter("password", "MSF RPC password (uses saved if not provided)", "string", False),
            ],
            category="msf"
        ))

        self.register(Tool(
            name="msf_search",
            description="Search for Metasploit modules by keyword.",
            function=self._tool_msf_search,
            parameters=[
                ToolParameter("query", "Search query (e.g., 'smb', 'apache', 'cve:2021')", "string", True),
            ],
            category="msf"
        ))

        self.register(Tool(
            name="msf_module_info",
            description="Get detailed information about a Metasploit module.",
            function=self._tool_msf_module_info,
            parameters=[
                ToolParameter("module_type", "Module type: exploit, auxiliary, post, payload", "string", True),
                ToolParameter("module_name", "Module name (e.g., 'windows/smb/ms17_010_eternalblue')", "string", True),
            ],
            category="msf"
        ))

        self.register(Tool(
            name="msf_module_options",
            description="Get available options for a Metasploit module.",
            function=self._tool_msf_module_options,
            parameters=[
                ToolParameter("module_type", "Module type: exploit, auxiliary, post, payload", "string", True),
                ToolParameter("module_name", "Module name", "string", True),
            ],
            category="msf"
        ))

        self.register(Tool(
            name="msf_execute",
            description="Execute a Metasploit module with specified options.",
            function=self._tool_msf_execute,
            parameters=[
                ToolParameter("module_type", "Module type: exploit, auxiliary, post", "string", True),
                ToolParameter("module_name", "Module name", "string", True),
                ToolParameter("options", "JSON object of module options (e.g., {\"RHOSTS\": \"192.168.1.1\"})", "string", True),
            ],
            category="msf"
        ))

        self.register(Tool(
            name="msf_sessions",
            description="List active Metasploit sessions.",
            function=self._tool_msf_sessions,
            parameters=[],
            category="msf"
        ))

        self.register(Tool(
            name="msf_session_command",
            description="Execute a command in a Metasploit session.",
            function=self._tool_msf_session_command,
            parameters=[
                ToolParameter("session_id", "Session ID", "string", True),
                ToolParameter("command", "Command to execute", "string", True),
            ],
            category="msf"
        ))

        self.register(Tool(
            name="msf_console",
            description="Run a command in the Metasploit console.",
            function=self._tool_msf_console,
            parameters=[
                ToolParameter("command", "Console command to run", "string", True),
            ],
            category="msf"
        ))

    # Built-in tool implementations

    def _tool_shell(self, command: str, timeout: int = 30) -> str:
        """Execute a shell command."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[stderr]: {result.stderr}"
            if result.returncode != 0:
                output += f"\n[exit code]: {result.returncode}"
            return output.strip() or "[no output]"
        except subprocess.TimeoutExpired:
            return f"[error]: Command timed out after {timeout} seconds"
        except Exception as e:
            return f"[error]: {str(e)}"

    def _tool_read_file(self, path: str, max_lines: int = None) -> str:
        """Read a file's contents."""
        path = Path(path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file():
            raise ValueError(f"Not a file: {path}")

        with open(path, 'r', errors='replace') as f:
            if max_lines:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        lines.append(f"... [{path.stat().st_size} bytes total, truncated at {max_lines} lines]")
                        break
                    lines.append(line.rstrip())
                return '\n'.join(lines)
            else:
                return f.read()

    def _tool_write_file(self, path: str, content: str) -> str:
        """Write content to a file."""
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {path}"

    def _tool_list_dir(self, path: str = ".", show_hidden: bool = False) -> str:
        """List directory contents."""
        path = Path(path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")
        if not path.is_dir():
            raise ValueError(f"Not a directory: {path}")

        entries = []
        for entry in sorted(path.iterdir()):
            if not show_hidden and entry.name.startswith('.'):
                continue
            prefix = "d " if entry.is_dir() else "f "
            entries.append(f"{prefix}{entry.name}")

        return '\n'.join(entries) if entries else "[empty directory]"

    def _tool_search_files(self, pattern: str, path: str = ".") -> str:
        """Search for files matching a pattern."""
        path = Path(path).expanduser()
        matches = list(path.glob(pattern))

        if not matches:
            return f"No files matching '{pattern}'"

        result = []
        for match in matches[:50]:  # Limit results
            result.append(str(match))

        if len(matches) > 50:
            result.append(f"... and {len(matches) - 50} more")

        return '\n'.join(result)

    def _tool_search_content(self, pattern: str, path: str = ".", file_pattern: str = None) -> str:
        """Search for content in files."""
        try:
            cmd = f"grep -rn '{pattern}' {path}"
            if file_pattern:
                cmd = f"grep -rn --include='{file_pattern}' '{pattern}' {path}"

            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            output = result.stdout.strip()
            if not output:
                return f"No matches found for '{pattern}'"

            # Limit output
            lines = output.split('\n')
            if len(lines) > 30:
                return '\n'.join(lines[:30]) + f"\n... and {len(lines) - 30} more matches"
            return output

        except subprocess.TimeoutExpired:
            return "[error]: Search timed out"
        except Exception as e:
            return f"[error]: {str(e)}"

    def _tool_create_module(self, name: str, category: str, code: str) -> str:
        """Create a new AUTARCH module in the modules/ directory."""
        import importlib.util as ilu

        valid_categories = ('defense', 'offense', 'counter', 'analyze', 'osint', 'simulate')
        category = category.lower().strip()
        if category not in valid_categories:
            return f"[error]: Invalid category '{category}'. Must be one of: {', '.join(valid_categories)}"

        # Sanitize name
        name = name.strip().replace(' ', '_').replace('-', '_').lower()
        if not name.replace('_', '').isalnum():
            return f"[error]: Invalid module name '{name}'. Use only letters, numbers, and underscores."

        # Check required attributes in source code
        required = ['DESCRIPTION', 'VERSION', 'CATEGORY', 'def run(']
        missing = [r for r in required if r not in code]
        if missing:
            return f"[error]: Module code is missing required elements: {', '.join(missing)}"

        # Determine modules directory
        modules_dir = Path(__file__).parent.parent / 'modules'
        module_path = modules_dir / f'{name}.py'

        if module_path.exists():
            return f"[error]: Module '{name}' already exists at {module_path}. Choose a different name."

        # Write the module file
        try:
            module_path.write_text(code, encoding='utf-8')
        except Exception as e:
            return f"[error]: Failed to write module: {e}"

        # Validate by attempting to import
        try:
            spec = ilu.spec_from_file_location(name, module_path)
            mod = ilu.module_from_spec(spec)
            spec.loader.exec_module(mod)

            # Verify it has run()
            if not hasattr(mod, 'run'):
                module_path.unlink()
                return "[error]: Module loaded but has no run() function. Module deleted."

        except Exception as e:
            # Import failed — delete the bad module
            try:
                module_path.unlink()
            except Exception:
                pass
            return f"[error]: Module failed to import: {e}. Module deleted."

        return f"Module '{name}' created successfully at {module_path}. Category: {category}. It is now available in the dashboard."

    def _tool_task_complete(self, summary: str) -> str:
        """Mark task as complete - this is a control signal."""
        return f"__TASK_COMPLETE__:{summary}"

    def _tool_ask_user(self, question: str) -> str:
        """Ask user a question - handled by agent loop."""
        return f"__ASK_USER__:{question}"

    # Metasploit tool implementations

    def _tool_msf_connect(self, password: str = None) -> str:
        """Connect to Metasploit RPC."""
        from .msf import get_msf_manager, MSFError

        msf = get_msf_manager()
        try:
            msf.connect(password)
            version = msf.rpc.get_version()
            return f"Connected to Metasploit {version.get('version', 'Unknown')}"
        except MSFError as e:
            return f"[error]: {e}"

    def _tool_msf_search(self, query: str) -> str:
        """Search for Metasploit modules."""
        from .msf import get_msf_manager, MSFError

        msf = get_msf_manager()
        if not msf.is_connected:
            return "[error]: Not connected to Metasploit. Use msf_connect first."

        try:
            results = msf.rpc.search_modules(query)
            if not results:
                return f"No modules found matching '{query}'"

            output = []
            for i, mod in enumerate(results[:20]):  # Limit to 20 results
                if isinstance(mod, dict):
                    name = mod.get('fullname', mod.get('name', 'Unknown'))
                    desc = mod.get('description', '')[:60]
                    output.append(f"{name}\n  {desc}")
                else:
                    output.append(str(mod))

            if len(results) > 20:
                output.append(f"\n... and {len(results) - 20} more results")

            return '\n'.join(output)
        except MSFError as e:
            return f"[error]: {e}"

    def _tool_msf_module_info(self, module_type: str, module_name: str) -> str:
        """Get module information."""
        from .msf import get_msf_manager, MSFError

        msf = get_msf_manager()
        if not msf.is_connected:
            return "[error]: Not connected to Metasploit. Use msf_connect first."

        try:
            info = msf.rpc.get_module_info(module_type, module_name)
            output = [
                f"Name: {info.name}",
                f"Type: {info.type}",
                f"Rank: {info.rank}",
                f"Description: {info.description[:200]}..." if len(info.description) > 200 else f"Description: {info.description}",
            ]
            if info.author:
                output.append(f"Authors: {', '.join(info.author[:3])}")
            return '\n'.join(output)
        except MSFError as e:
            return f"[error]: {e}"

    def _tool_msf_module_options(self, module_type: str, module_name: str) -> str:
        """Get module options."""
        from .msf import get_msf_manager, MSFError

        msf = get_msf_manager()
        if not msf.is_connected:
            return "[error]: Not connected to Metasploit. Use msf_connect first."

        try:
            options = msf.rpc.get_module_options(module_type, module_name)
            output = []
            for name, details in options.items():
                if isinstance(details, dict):
                    required = "*" if details.get('required', False) else ""
                    default = details.get('default', '')
                    desc = details.get('desc', '')[:50]
                    output.append(f"{name}{required}: {desc} [default: {default}]")
                else:
                    output.append(f"{name}: {details}")
            return '\n'.join(output) if output else "No options available"
        except MSFError as e:
            return f"[error]: {e}"

    def _tool_msf_execute(self, module_type: str, module_name: str, options: str) -> str:
        """Execute a Metasploit module."""
        from .msf import get_msf_manager, MSFError

        msf = get_msf_manager()
        if not msf.is_connected:
            return "[error]: Not connected to Metasploit. Use msf_connect first."

        try:
            opts = json.loads(options) if isinstance(options, str) else options
        except json.JSONDecodeError:
            return "[error]: Invalid JSON in options parameter"

        try:
            result = msf.rpc.execute_module(module_type, module_name, opts)
            job_id = result.get('job_id')
            uuid = result.get('uuid')
            return f"Module executed. Job ID: {job_id}, UUID: {uuid}"
        except MSFError as e:
            return f"[error]: {e}"

    def _tool_msf_sessions(self) -> str:
        """List active sessions."""
        from .msf import get_msf_manager, MSFError

        msf = get_msf_manager()
        if not msf.is_connected:
            return "[error]: Not connected to Metasploit. Use msf_connect first."

        try:
            sessions = msf.rpc.list_sessions()
            if not sessions:
                return "No active sessions"

            output = []
            for sid, info in sessions.items():
                if isinstance(info, dict):
                    stype = info.get('type', 'Unknown')
                    target = info.get('target_host', 'Unknown')
                    user = info.get('username', '')
                    output.append(f"[{sid}] {stype} - {target} ({user})")
                else:
                    output.append(f"[{sid}] {info}")
            return '\n'.join(output)
        except MSFError as e:
            return f"[error]: {e}"

    def _tool_msf_session_command(self, session_id: str, command: str) -> str:
        """Execute command in a session."""
        from .msf import get_msf_manager, MSFError

        msf = get_msf_manager()
        if not msf.is_connected:
            return "[error]: Not connected to Metasploit. Use msf_connect first."

        try:
            msf.rpc.session_shell_write(session_id, command)
            import time
            time.sleep(1)  # Wait for command execution
            output = msf.rpc.session_shell_read(session_id)
            return output if output else "[no output]"
        except MSFError as e:
            return f"[error]: {e}"

    def _tool_msf_console(self, command: str) -> str:
        """Run a console command."""
        from .msf import get_msf_manager, MSFError

        msf = get_msf_manager()
        if not msf.is_connected:
            return "[error]: Not connected to Metasploit. Use msf_connect first."

        try:
            output = msf.rpc.run_console_command(command)
            return output if output else "[no output]"
        except MSFError as e:
            return f"[error]: {e}"


# Global tool registry
_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
