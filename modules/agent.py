"""
AUTARCH Agent Module
Interactive interface for running autonomous agent tasks

This module provides an interface to give tasks to the autonomous agent
and watch it work through them step by step.
"""

import sys
from pathlib import Path

# Module metadata
DESCRIPTION = "Autonomous agent for task execution"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "core"

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.agent import Agent, AgentState, AgentStep, AgentResult
from core.tools import get_tool_registry
from core.llm import get_llm, LLMError
from core.banner import Colors, clear_screen, display_banner


class AgentInterface:
    """Interactive interface for the AUTARCH agent."""

    def __init__(self):
        self.agent = None
        self.llm = get_llm()
        self.tools = get_tool_registry()

    def print_status(self, message: str, status: str = "info"):
        """Print a status message."""
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def print_header(self, text: str):
        """Print a section header."""
        print(f"\n{Colors.BOLD}{Colors.WHITE}{text}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")

    def show_tools(self):
        """Display available tools."""
        self.print_header("Available Tools")

        tools = self.tools.list_tools()
        for tool in tools:
            print(f"\n  {Colors.CYAN}{tool.name}{Colors.RESET} [{tool.category}]")
            print(f"  {Colors.DIM}{tool.description}{Colors.RESET}")
            if tool.parameters:
                for param in tool.parameters:
                    req = "*" if param.required else ""
                    print(f"    - {param.name}{req}: {param.description}")

    def on_step_callback(self, step: AgentStep):
        """Callback for when agent completes a step."""
        print(f"\n{Colors.DIM}{'─' * 40}{Colors.RESET}")

    def on_state_callback(self, state: AgentState):
        """Callback for agent state changes."""
        state_colors = {
            AgentState.IDLE: Colors.WHITE,
            AgentState.THINKING: Colors.MAGENTA,
            AgentState.EXECUTING: Colors.BLUE,
            AgentState.WAITING_USER: Colors.YELLOW,
            AgentState.COMPLETE: Colors.GREEN,
            AgentState.ERROR: Colors.RED,
        }
        color = state_colors.get(state, Colors.WHITE)
        # Only show state for key transitions
        if state in [AgentState.COMPLETE, AgentState.ERROR]:
            print(f"{color}[State: {state.value}]{Colors.RESET}")

    def run_task(self, task: str) -> AgentResult:
        """Run a task through the agent.

        Args:
            task: Task description.

        Returns:
            AgentResult with execution details.
        """
        self.agent = Agent(
            llm=self.llm,
            tools=self.tools,
            max_steps=20,
            verbose=True
        )

        self.agent.on_step = self.on_step_callback
        self.agent.on_state_change = self.on_state_callback

        return self.agent.run(task)

    def interactive_loop(self):
        """Run interactive task input loop."""
        self.print_header("Agent Interface")
        print(f"\n{Colors.WHITE}Enter a task for the agent to complete.")
        print(f"Type 'tools' to see available tools.")
        print(f"Type 'exit' to return to main menu.{Colors.RESET}\n")

        while True:
            try:
                print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")
                task = input(f"\n{Colors.GREEN}Task:{Colors.RESET} ").strip()

                if not task:
                    continue

                if task.lower() == 'exit':
                    break

                if task.lower() == 'tools':
                    self.show_tools()
                    continue

                if task.lower() == 'help':
                    print(f"\n{Colors.WHITE}Commands:{Colors.RESET}")
                    print(f"  {Colors.CYAN}tools{Colors.RESET}  - Show available tools")
                    print(f"  {Colors.CYAN}exit{Colors.RESET}   - Return to main menu")
                    print(f"  {Colors.CYAN}help{Colors.RESET}   - Show this help")
                    print(f"\n{Colors.WHITE}Or enter a task description for the agent.{Colors.RESET}")
                    continue

                # Run the task
                print(f"\n{Colors.CYAN}[*] Starting agent...{Colors.RESET}\n")

                result = self.run_task(task)

                # Show result summary
                print(f"\n{Colors.DIM}{'═' * 50}{Colors.RESET}")
                if result.success:
                    print(f"{Colors.GREEN}[+] Task completed successfully{Colors.RESET}")
                    print(f"\n{Colors.WHITE}Summary:{Colors.RESET} {result.summary}")
                else:
                    print(f"{Colors.RED}[X] Task failed{Colors.RESET}")
                    if result.error:
                        print(f"{Colors.RED}Error:{Colors.RESET} {result.error}")
                    if result.summary:
                        print(f"{Colors.WHITE}Summary:{Colors.RESET} {result.summary}")

                print(f"\n{Colors.DIM}Steps taken: {len(result.steps)}{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                print(f"\n\n{Colors.YELLOW}[!] Interrupted{Colors.RESET}")
                break

    def run(self):
        """Module entry point."""
        clear_screen()
        display_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  AUTARCH Autonomous Agent{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")

        # Check if model is loaded
        if not self.llm.is_loaded:
            self.print_status("Loading model...", "info")
            try:
                self.llm.load_model(verbose=True)
            except LLMError as e:
                self.print_status(f"Failed to load model: {e}", "error")
                self.print_status("Please run setup to configure a model.", "warning")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                return

        self.interactive_loop()


def run():
    """Module entry point."""
    interface = AgentInterface()
    interface.run()


if __name__ == "__main__":
    run()
