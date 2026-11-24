"""Interactive terminal menu wizard for AI Red Team Security Validation."""

from pathlib import Path
from typing import Callable, List, Optional

from agent_bg_sec.core.exceptions import AgentSecError
from agent_bg_sec.core.logger import TerminalFormatter


class InteractiveMenuSession:
    """Provides a guided, interactive menu loop when `agent-sec` is launched without subcommands."""

    def __init__(
        self,
        execute_cli_callback: Callable[[List[str]], int],
        formatter: Optional[TerminalFormatter] = None,
        input_fn: Callable[[str], str] = input,
    ) -> None:
        self.execute_cli_callback = execute_cli_callback
        self.formatter = formatter or TerminalFormatter()
        self.input_fn = input_fn
        self.repo_root = Path(__file__).resolve().parents[3]
        self.examples_dir = self.repo_root / "examples"

    def run_loop(self) -> int:
        """Display the interactive main menu in a loop until the user chooses Exit."""
        fmt = self.formatter
        while True:
            print("\n" + fmt.banner(
                "AI RED TEAM SECURITY VALIDATOR CONSOLE",
                "Interactive Terminal Mode | Select an operation below",
            ))
            menu_rows = [
                ["[1]", "One-Time Test of a Local Agent Folder", "Introspect local agent folder, run Red Team, and output score (%)"],
                ["[2]", "One-Time Test of a GitHub Repository", "Clone GitHub repo, run Red Team attacks, and output score (%)"],
                ["[3]", "Continuous GitHub Push Watcher (Auto-Test)", "Watch GitHub repo for new pushes -> auto-fetch, test & score (%)"],
                ["[4]", "Quick-Test Built-in Sample AI Agents", "Test Safe Banking, Vulnerable DevOps, or Healthcare RAG agent"],
                ["[5]", "Run Experimental Comparative Benchmark", "Compare Traditional vs. AI Red-Team Security Validation"],
                ["[6]", "Check OpenRouter LLM API & .env Connection", "Verify OPENROUTER_API_KEY and live model response"],
                ["[7]", "Test with Custom Risk Threshold (%)", "Run validation using a custom max acceptable Risk Score (%)"],
                ["[0]", "Exit Application", "Quit the interactive console"],
            ]
            print(fmt.format_table(["Option", "Feature / Action", "Description"], menu_rows))

            choice = self._prompt("Select an option [0-7]: ").strip().lower()
            if choice in ("0", "q", "quit", "exit"):
                print(fmt.colorize("\n[INFO] Exiting AI Red Team Security Validator Console. Goodbye!", fmt.CYAN + fmt.BOLD))
                return 0

            try:
                if choice == "1":
                    self._menu_test_local_folder()
                elif choice == "2":
                    self._menu_test_github_once()
                elif choice == "3":
                    self._menu_watch_github_continuous()
                elif choice == "4":
                    self._menu_quick_sample_agents()
                elif choice == "5":
                    self.execute_cli_callback(["benchmark"])
                elif choice == "6":
                    self.execute_cli_callback(["test-openrouter"])
                elif choice == "7":
                    self._menu_custom_threshold_scan()
                else:
                    print(fmt.colorize(f"\n[WARN] Invalid choice '{choice}'. Please enter a number from 0 to 7.", fmt.YELLOW))
            except KeyboardInterrupt:
                print(fmt.colorize("\n[INFO] Operation cancelled. Returning to main menu...", fmt.YELLOW))
            except AgentSecError as exc:
                print(fmt.colorize(f"\n{exc.format_error()}", fmt.RED + fmt.BOLD))
            except Exception as exc:
                print(fmt.colorize(f"\n[ERROR] Unexpected error caught safely: {exc}", fmt.RED + fmt.BOLD))

            if not self._pause_or_exit():
                return 0

    def _menu_test_local_folder(self) -> None:
        fmt = self.formatter
        print(fmt.section("Option 1: One-Time Test of a Local AI Agent Folder"))
        raw_path = self._prompt("Enter the file or folder path of the target AI agent: ").strip()
        if not raw_path:
            print(fmt.colorize("[WARN] Folder path cannot be empty. Cancelled.", fmt.YELLOW))
            return

        self.execute_cli_callback(["test-folder", raw_path])

    def _menu_test_github_once(self) -> None:
        fmt = self.formatter
        print(fmt.section("Option 2: One-Time Clone & Test of a GitHub Repository"))
        repo_url = self._prompt("Enter the GitHub repository URL (e.g. https://github.com/owner/repo): ").strip()
        if not repo_url:
            print(fmt.colorize("[WARN] GitHub URL cannot be empty. Cancelled.", fmt.YELLOW))
            return

        branch = self._prompt("Enter branch name (press Enter for default branch): ").strip()
        subpath = self._prompt("Enter subfolder inside repo if any (press Enter for root): ").strip()

        argv = ["test-github", repo_url]
        if branch:
            argv.extend(["--branch", branch])
        if subpath:
            argv.extend(["--subpath", subpath])
        self.execute_cli_callback(argv)

    def _menu_watch_github_continuous(self) -> None:
        fmt = self.formatter
        print(fmt.section("Option 3: Continuous GitHub Push Watcher (Auto-Fetch, Test & Score)"))
        repo_url = self._prompt("Enter the GitHub repository URL to watch: ").strip()
        if not repo_url:
            print(fmt.colorize("[WARN] GitHub URL cannot be empty. Cancelled.", fmt.YELLOW))
            return

        branch = self._prompt("Enter branch name to monitor (press Enter for default HEAD): ").strip()
        subpath = self._prompt("Enter subfolder inside repo if any (press Enter for root): ").strip()
        interval_raw = self._prompt("Enter polling interval in seconds [default: 30]: ").strip()
        interval = "30"
        if interval_raw:
            if not interval_raw.isdigit() or int(interval_raw) <= 0:
                print(fmt.colorize("[WARN] Invalid interval; using default 30 seconds.", fmt.YELLOW))
            else:
                interval = interval_raw

        max_cycles_raw = self._prompt(
            "Enter max watch cycles (press Enter for continuous infinite monitoring, or e.g. 3): "
        ).strip()

        argv = ["watch-github", repo_url, "--interval", interval]
        if branch:
            argv.extend(["--branch", branch])
        if subpath:
            argv.extend(["--subpath", subpath])
        if max_cycles_raw and max_cycles_raw.isdigit() and int(max_cycles_raw) > 0:
            argv.extend(["--max-cycles", max_cycles_raw])

        print(fmt.colorize("\n[INFO] Starting continuous watcher (Press Ctrl+C anytime to stop and return to menu)...", fmt.CYAN))
        self.execute_cli_callback(argv)

    def _menu_quick_sample_agents(self) -> None:
        fmt = self.formatter
        print(fmt.section("Option 4: Quick-Test Built-in Sample AI Agents"))
        samples = [
            ("1", "safe_banking_agent", "Hardened FinTech/Banking Agent (Expected: 100.00% Security Score -> PASSED)"),
            ("2", "vulnerable_devops_agent", "Vulnerable DevOps Shell Agent (Expected: 11.89% Security Score -> FAILED)"),
            ("3", "healthcare_rag_agent", "Partially Guarded Healthcare RAG Agent (Expected: 50.56% Security Score -> FAILED)"),
            ("4", "ALL", "Test all 3 sample agents sequentially"),
        ]
        print(fmt.format_table(["Choice", "Agent Folder", "Profile"], [[s[0], s[1], s[2]] for s in samples]))
        pick = self._prompt("Choose a sample agent to test [1-4]: ").strip()
        if pick == "1":
            self.execute_cli_callback(["test-folder", str(self.examples_dir / "safe_banking_agent")])
        elif pick == "2":
            self.execute_cli_callback(["test-folder", str(self.examples_dir / "vulnerable_devops_agent")])
        elif pick == "3":
            self.execute_cli_callback(["test-folder", str(self.examples_dir / "healthcare_rag_agent")])
        elif pick == "4":
            for folder_name in ("safe_banking_agent", "vulnerable_devops_agent", "healthcare_rag_agent"):
                self.execute_cli_callback(["test-folder", str(self.examples_dir / folder_name)])
        else:
            print(fmt.colorize("[WARN] Invalid sample selection.", fmt.YELLOW))

    def _menu_custom_threshold_scan(self) -> None:
        fmt = self.formatter
        print(fmt.section("Option 7: Run Folder Test with Custom Risk Threshold (%)"))
        thresh_str = self._prompt("Enter max acceptable Risk Score % (0-100) [default: 20.0]: ").strip() or "20.0"
        try:
            val = float(thresh_str)
            if not (0.0 <= val <= 100.0):
                raise ValueError("Out of bounds")
        except ValueError:
            print(fmt.colorize("[WARN] Threshold must be a number between 0 and 100.", fmt.YELLOW))
            return

        target = self._prompt(
            "Enter target agent folder path [press Enter for examples/healthcare_rag_agent]: "
        ).strip() or str(self.examples_dir / "healthcare_rag_agent")
        self.execute_cli_callback(["--max-risk", str(val), "test-folder", target])

    def _prompt(self, message: str) -> str:
        try:
            return self.input_fn(self.formatter.colorize(message, self.formatter.BOLD + self.formatter.CYAN))
        except EOFError:
            return "0"

    def _pause_or_exit(self) -> bool:
        try:
            ans = self.input_fn(
                self.formatter.colorize(
                    "\nPress [Enter] to return to the Main Menu (or type 'q' to quit): ",
                    self.formatter.DIM,
                )
            ).strip().lower()
            return ans not in ("q", "quit", "exit", "0")
        except EOFError:
            return False
