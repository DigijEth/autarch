"""
AUTARCH Chat Module
Interactive chat interface for the LLM

This module provides a command-line chat interface to interact with the loaded model.
"""

import sys
from pathlib import Path

# Module metadata
DESCRIPTION = "Interactive chat with the LLM"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "core"

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.llm import get_llm, LLMError
from core.banner import Colors, clear_screen, display_banner


class ChatInterface:
    """Interactive chat interface for AUTARCH LLM."""

    COMMANDS = {
        '/help': 'Show available commands',
        '/clear': 'Clear conversation history',
        '/history': 'Show conversation history',
        '/info': 'Show model information',
        '/system': 'Set system prompt (e.g., /system You are a helpful assistant)',
        '/temp': 'Set temperature (e.g., /temp 0.8)',
        '/tokens': 'Set max tokens (e.g., /tokens 1024)',
        '/stream': 'Toggle streaming mode',
        '/exit': 'Exit chat',
    }

    def __init__(self):
        self.llm = get_llm()
        self.system_prompt = "You are AUTARCH, an AI assistant created by darkHal and Setec Security Labs. You are helpful, knowledgeable, and direct in your responses."
        self.streaming = True
        self.temp_override = None
        self.tokens_override = None

    def print_status(self, message: str, status: str = "info"):
        """Print a status message."""
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def print_help(self):
        """Display available commands."""
        print(f"\n{Colors.BOLD}{Colors.WHITE}Available Commands:{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")
        for cmd, desc in self.COMMANDS.items():
            print(f"  {Colors.CYAN}{cmd:12}{Colors.RESET} {desc}")
        print()

    def print_history(self):
        """Display conversation history."""
        history = self.llm.get_history()
        if not history:
            self.print_status("No conversation history", "info")
            return

        print(f"\n{Colors.BOLD}{Colors.WHITE}Conversation History:{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")

        for msg in history:
            role = msg['role']
            content = msg['content']

            if role == 'system':
                print(f"\n{Colors.MAGENTA}[System]{Colors.RESET}")
                print(f"  {Colors.DIM}{content[:100]}...{Colors.RESET}" if len(content) > 100 else f"  {Colors.DIM}{content}{Colors.RESET}")
            elif role == 'user':
                print(f"\n{Colors.GREEN}[You]{Colors.RESET}")
                print(f"  {content}")
            elif role == 'assistant':
                print(f"\n{Colors.CYAN}[AUTARCH]{Colors.RESET}")
                # Truncate long responses in history view
                if len(content) > 200:
                    print(f"  {content[:200]}...")
                else:
                    print(f"  {content}")
        print()

    def print_model_info(self):
        """Display model information."""
        info = self.llm.get_model_info()

        print(f"\n{Colors.BOLD}{Colors.WHITE}Model Information:{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")

        if info['loaded']:
            print(f"  {Colors.CYAN}Model:{Colors.RESET} {info['model_name']}")
            print(f"  {Colors.CYAN}Context Size:{Colors.RESET} {info['n_ctx']}")
            print(f"  {Colors.CYAN}Vocabulary:{Colors.RESET} {info['n_vocab']}")
            print(f"  {Colors.CYAN}Streaming:{Colors.RESET} {'Enabled' if self.streaming else 'Disabled'}")

            if self.temp_override:
                print(f"  {Colors.CYAN}Temperature:{Colors.RESET} {self.temp_override} (override)")
            if self.tokens_override:
                print(f"  {Colors.CYAN}Max Tokens:{Colors.RESET} {self.tokens_override} (override)")
        else:
            print(f"  {Colors.YELLOW}No model loaded{Colors.RESET}")
        print()

    def handle_command(self, command: str) -> bool:
        """Handle a chat command.

        Args:
            command: The command string.

        Returns:
            True if should continue chat, False if should exit.
        """
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd == '/help':
            self.print_help()

        elif cmd == '/clear':
            self.llm.clear_history()
            self.print_status("Conversation history cleared", "success")

        elif cmd == '/history':
            self.print_history()

        elif cmd == '/info':
            self.print_model_info()

        elif cmd == '/system':
            if args:
                self.system_prompt = args
                self.llm.clear_history()  # Clear history when changing system prompt
                self.print_status(f"System prompt set: {args[:50]}...", "success")
            else:
                print(f"  {Colors.CYAN}Current:{Colors.RESET} {self.system_prompt}")

        elif cmd == '/temp':
            if args:
                try:
                    temp = float(args)
                    if 0.0 <= temp <= 2.0:
                        self.temp_override = temp
                        self.print_status(f"Temperature set to {temp}", "success")
                    else:
                        self.print_status("Temperature must be between 0.0 and 2.0", "error")
                except ValueError:
                    self.print_status("Invalid temperature value", "error")
            else:
                self.print_status(f"Current temperature: {self.temp_override or 'default'}", "info")

        elif cmd == '/tokens':
            if args:
                try:
                    tokens = int(args)
                    if tokens > 0:
                        self.tokens_override = tokens
                        self.print_status(f"Max tokens set to {tokens}", "success")
                    else:
                        self.print_status("Max tokens must be positive", "error")
                except ValueError:
                    self.print_status("Invalid token value", "error")
            else:
                self.print_status(f"Current max tokens: {self.tokens_override or 'default'}", "info")

        elif cmd == '/stream':
            self.streaming = not self.streaming
            self.print_status(f"Streaming {'enabled' if self.streaming else 'disabled'}", "success")

        elif cmd in ['/exit', '/quit', '/q']:
            return False

        else:
            self.print_status(f"Unknown command: {cmd}. Type /help for commands.", "warning")

        return True

    def chat_loop(self):
        """Main chat loop."""
        print(f"\n{Colors.GREEN}[+] Chat started. Type /help for commands, /exit to quit.{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

        while True:
            try:
                # Get user input
                user_input = input(f"{Colors.GREEN}You:{Colors.RESET} ").strip()

                if not user_input:
                    continue

                # Handle commands
                if user_input.startswith('/'):
                    if not self.handle_command(user_input):
                        break
                    continue

                # Generate response
                print(f"\n{Colors.CYAN}AUTARCH:{Colors.RESET} ", end="", flush=True)

                kwargs = {}
                if self.temp_override is not None:
                    kwargs['temperature'] = self.temp_override
                if self.tokens_override is not None:
                    kwargs['max_tokens'] = self.tokens_override

                try:
                    if self.streaming:
                        # Streaming response
                        for token in self.llm.chat(
                            user_input,
                            system_prompt=self.system_prompt,
                            stream=True,
                            **kwargs
                        ):
                            print(token, end="", flush=True)
                        print("\n")
                    else:
                        # Non-streaming response
                        response = self.llm.chat(
                            user_input,
                            system_prompt=self.system_prompt,
                            stream=False,
                            **kwargs
                        )
                        print(f"{response}\n")

                except LLMError as e:
                    print()
                    self.print_status(f"Generation error: {e}", "error")

            except (EOFError, KeyboardInterrupt):
                print(f"\n\n{Colors.CYAN}Chat ended.{Colors.RESET}")
                break

    def run(self):
        """Run the chat interface."""
        clear_screen()
        display_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  AUTARCH Chat Interface{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")

        # Check if model is loaded
        if not self.llm.is_loaded:
            self.print_status("Loading model...", "info")
            try:
                self.llm.load_model(verbose=True)
            except LLMError as e:
                self.print_status(f"Failed to load model: {e}", "error")
                self.print_status("Please run setup to configure a model.", "warning")
                return

        self.print_model_info()
        self.chat_loop()


def run():
    """Module entry point."""
    chat = ChatInterface()
    chat.run()


if __name__ == "__main__":
    run()
