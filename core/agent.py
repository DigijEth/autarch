"""
AUTARCH Agent System
Autonomous agent that uses LLM to accomplish tasks with tools
"""

import re
import json
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from .llm import get_llm, LLM, LLMError
from .tools import get_tool_registry, ToolRegistry
from .banner import Colors


class AgentState(Enum):
    """Agent execution states."""
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING_USER = "waiting_user"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class AgentStep:
    """Record of a single agent step."""
    thought: str
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    tool_result: Optional[str] = None
    error: Optional[str] = None


@dataclass
class AgentResult:
    """Result of an agent task execution."""
    success: bool
    summary: str
    steps: List[AgentStep] = field(default_factory=list)
    error: Optional[str] = None


class Agent:
    """Autonomous agent that uses LLM and tools to accomplish tasks."""

    SYSTEM_PROMPT = """You are AUTARCH, an autonomous AI agent created by darkHal and Setec Security Labs.

Your purpose is to accomplish tasks using the tools available to you. You think step by step, use tools to gather information and take actions, then continue until the task is complete.

## How to respond

You MUST respond in the following format for EVERY response:

THOUGHT: [Your reasoning about what to do next]
ACTION: [tool_name]
PARAMS: {"param1": "value1", "param2": "value2"}

OR when the task is complete:

THOUGHT: [Summary of what was accomplished]
ACTION: task_complete
PARAMS: {"summary": "Description of completed work"}

OR when you need user input:

THOUGHT: [Why you need to ask the user]
ACTION: ask_user
PARAMS: {"question": "Your question"}

## Rules
1. Always start with THOUGHT to explain your reasoning
2. Always specify exactly one ACTION
3. Always provide PARAMS as valid JSON (even if empty: {})
4. Use tools to verify your work - don't assume success
5. If a tool fails, analyze the error and try a different approach
6. Only use task_complete when the task is fully done

{tools_description}
"""

    def __init__(
        self,
        llm: LLM = None,
        tools: ToolRegistry = None,
        max_steps: int = 20,
        verbose: bool = True
    ):
        """Initialize the agent.

        Args:
            llm: LLM instance to use. Uses global if not provided.
            tools: Tool registry to use. Uses global if not provided.
            max_steps: Maximum steps before stopping.
            verbose: Whether to print progress.
        """
        self.llm = llm or get_llm()
        self.tools = tools or get_tool_registry()
        self.max_steps = max_steps
        self.verbose = verbose

        self.state = AgentState.IDLE
        self.current_task: Optional[str] = None
        self.steps: List[AgentStep] = []
        self.conversation: List[Dict[str, str]] = []

        # Callbacks
        self.on_step: Optional[Callable[[AgentStep], None]] = None
        self.on_state_change: Optional[Callable[[AgentState], None]] = None

    def _set_state(self, state: AgentState):
        """Update agent state and notify callback."""
        self.state = state
        if self.on_state_change:
            self.on_state_change(state)

    def _log(self, message: str, level: str = "info"):
        """Log a message if verbose mode is on."""
        if not self.verbose:
            return

        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED,
            "thought": Colors.MAGENTA,
            "action": Colors.BLUE,
            "result": Colors.WHITE,
        }
        symbols = {
            "info": "*",
            "success": "+",
            "warning": "!",
            "error": "X",
            "thought": "?",
            "action": ">",
            "result": "<",
        }

        color = colors.get(level, Colors.WHITE)
        symbol = symbols.get(level, "*")
        print(f"{color}[{symbol}] {message}{Colors.RESET}")

    def _build_system_prompt(self) -> str:
        """Build the system prompt with tools description."""
        tools_desc = self.tools.get_tools_prompt()
        return self.SYSTEM_PROMPT.format(tools_description=tools_desc)

    def _parse_response(self, response: str) -> tuple[str, str, Dict[str, Any]]:
        """Parse LLM response into thought, action, and params.

        Args:
            response: The raw LLM response.

        Returns:
            Tuple of (thought, action_name, params_dict)

        Raises:
            ValueError: If response cannot be parsed.
        """
        # Extract THOUGHT
        thought_match = re.search(r'THOUGHT:\s*(.+?)(?=ACTION:|$)', response, re.DOTALL)
        thought = thought_match.group(1).strip() if thought_match else ""

        # Extract ACTION
        action_match = re.search(r'ACTION:\s*(\w+)', response)
        if not action_match:
            raise ValueError("No ACTION found in response")
        action = action_match.group(1).strip()

        # Extract PARAMS
        params_match = re.search(r'PARAMS:\s*(\{.*?\})', response, re.DOTALL)
        if params_match:
            try:
                params = json.loads(params_match.group(1))
            except json.JSONDecodeError:
                # Try to fix common JSON issues
                params_str = params_match.group(1)
                # Replace single quotes with double quotes
                params_str = params_str.replace("'", '"')
                try:
                    params = json.loads(params_str)
                except json.JSONDecodeError:
                    params = {}
        else:
            params = {}

        return thought, action, params

    def _execute_tool(self, tool_name: str, params: Dict[str, Any]) -> str:
        """Execute a tool and return the result.

        Args:
            tool_name: Name of the tool to execute.
            params: Parameters for the tool.

        Returns:
            Tool result string.
        """
        result = self.tools.execute(tool_name, **params)

        if result["success"]:
            return str(result["result"])
        else:
            return f"[Error]: {result['error']}"

    def run(self, task: str, user_input_handler: Callable[[str], str] = None,
            step_callback: Optional[Callable[['AgentStep'], None]] = None) -> AgentResult:
        """Run the agent on a task.

        Args:
            task: The task description.
            user_input_handler: Callback for handling ask_user actions.
                               If None, uses default input().
            step_callback: Optional per-step callback invoked after each step completes.
                          Overrides self.on_step for this run if provided.

        Returns:
            AgentResult with execution details.
        """
        if step_callback is not None:
            self.on_step = step_callback
        self.current_task = task
        self.steps = []
        self.conversation = []

        # Ensure model is loaded
        if not self.llm.is_loaded:
            self._log("Loading model...", "info")
            try:
                self.llm.load_model(verbose=self.verbose)
            except LLMError as e:
                self._set_state(AgentState.ERROR)
                return AgentResult(
                    success=False,
                    summary="Failed to load model",
                    error=str(e)
                )

        self._set_state(AgentState.THINKING)
        self._log(f"Starting task: {task}", "info")

        # Build initial prompt
        system_prompt = self._build_system_prompt()
        self.conversation.append({"role": "system", "content": system_prompt})
        self.conversation.append({"role": "user", "content": f"Task: {task}"})

        step_count = 0

        while step_count < self.max_steps:
            step_count += 1
            self._log(f"Step {step_count}/{self.max_steps}", "info")

            # Generate response
            self._set_state(AgentState.THINKING)
            try:
                prompt = self._build_prompt()
                response = self.llm.generate(
                    prompt,
                    stop=["OBSERVATION:", "\nUser:", "\nTask:"],
                    temperature=0.3,  # Lower temperature for more focused responses
                )
            except LLMError as e:
                self._set_state(AgentState.ERROR)
                return AgentResult(
                    success=False,
                    summary="LLM generation failed",
                    steps=self.steps,
                    error=str(e)
                )

            # Parse response
            try:
                thought, action, params = self._parse_response(response)
            except ValueError as e:
                self._log(f"Failed to parse response: {e}", "error")
                self._log(f"Raw response: {response[:200]}...", "warning")
                # Add error feedback and continue
                self.conversation.append({
                    "role": "assistant",
                    "content": response
                })
                self.conversation.append({
                    "role": "user",
                    "content": "Error: Could not parse your response. Please use the exact format:\nTHOUGHT: [reasoning]\nACTION: [tool_name]\nPARAMS: {\"param\": \"value\"}"
                })
                continue

            self._log(f"Thought: {thought[:100]}..." if len(thought) > 100 else f"Thought: {thought}", "thought")
            self._log(f"Action: {action}", "action")

            step = AgentStep(thought=thought, tool_name=action, tool_args=params)

            # Handle task_complete
            if action == "task_complete":
                summary = params.get("summary", thought)
                step.tool_result = summary
                self.steps.append(step)

                if self.on_step:
                    self.on_step(step)

                self._set_state(AgentState.COMPLETE)
                self._log(f"Task complete: {summary}", "success")

                return AgentResult(
                    success=True,
                    summary=summary,
                    steps=self.steps
                )

            # Handle ask_user
            if action == "ask_user":
                question = params.get("question", "What should I do?")
                self._set_state(AgentState.WAITING_USER)
                self._log(f"Agent asks: {question}", "info")

                if user_input_handler:
                    user_response = user_input_handler(question)
                else:
                    print(f"\n{Colors.YELLOW}Agent question: {question}{Colors.RESET}")
                    user_response = input(f"{Colors.GREEN}Your answer: {Colors.RESET}").strip()

                step.tool_result = f"User response: {user_response}"
                self.steps.append(step)

                if self.on_step:
                    self.on_step(step)

                # Add to conversation
                self.conversation.append({
                    "role": "assistant",
                    "content": f"THOUGHT: {thought}\nACTION: {action}\nPARAMS: {json.dumps(params)}"
                })
                self.conversation.append({
                    "role": "user",
                    "content": f"OBSERVATION: User responded: {user_response}"
                })
                continue

            # Execute tool
            self._set_state(AgentState.EXECUTING)
            self._log(f"Executing: {action}({params})", "action")

            result = self._execute_tool(action, params)
            step.tool_result = result
            self.steps.append(step)

            if self.on_step:
                self.on_step(step)

            # Truncate long results for display
            display_result = result[:200] + "..." if len(result) > 200 else result
            self._log(f"Result: {display_result}", "result")

            # Add to conversation
            self.conversation.append({
                "role": "assistant",
                "content": f"THOUGHT: {thought}\nACTION: {action}\nPARAMS: {json.dumps(params)}"
            })
            self.conversation.append({
                "role": "user",
                "content": f"OBSERVATION: {result}"
            })

        # Max steps reached
        self._set_state(AgentState.ERROR)
        self._log(f"Max steps ({self.max_steps}) reached", "warning")

        return AgentResult(
            success=False,
            summary="Max steps reached without completing task",
            steps=self.steps,
            error=f"Exceeded maximum of {self.max_steps} steps"
        )

    def _build_prompt(self) -> str:
        """Build the full prompt from conversation history."""
        parts = []
        for msg in self.conversation:
            role = msg["role"]
            content = msg["content"]

            if role == "system":
                parts.append(f"<|im_start|>system\n{content}<|im_end|>")
            elif role == "user":
                parts.append(f"<|im_start|>user\n{content}<|im_end|>")
            elif role == "assistant":
                parts.append(f"<|im_start|>assistant\n{content}<|im_end|>")

        parts.append("<|im_start|>assistant\n")
        return "\n".join(parts)

    def get_steps_summary(self) -> str:
        """Get a formatted summary of all steps taken."""
        if not self.steps:
            return "No steps executed"

        lines = []
        for i, step in enumerate(self.steps, 1):
            lines.append(f"Step {i}:")
            lines.append(f"  Thought: {step.thought[:80]}...")
            if step.tool_name:
                lines.append(f"  Action: {step.tool_name}")
            if step.tool_result:
                result_preview = step.tool_result[:80] + "..." if len(step.tool_result) > 80 else step.tool_result
                lines.append(f"  Result: {result_preview}")
            lines.append("")

        return "\n".join(lines)
