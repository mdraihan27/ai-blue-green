"""Command-line argument router supporting local folder test, GitHub test, continuous GitHub watcher, Blue-Green status/rollback, and benchmark."""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from agent_bg_sec.cli.interactive_menu import InteractiveMenuSession
from agent_bg_sec.cli.pipeline_controller import ValidationPipelineController
from agent_bg_sec.core.config import AppConfig
from agent_bg_sec.core.env_loader import DotEnvLoader
from agent_bg_sec.core.exceptions import AgentSecError
from agent_bg_sec.core.logger import AuditLogger, TerminalFormatter
from agent_bg_sec.core.models import AgentManifest, RiskAssessment
from agent_bg_sec.core.openrouter_client import OpenRouterClient
from agent_bg_sec.ingestion.continuous_watcher import ContinuousGitHubWatcher
from agent_bg_sec.ingestion.github_ingestor import GitHubRepoIngestor
from agent_bg_sec.ingestion.local_folder_ingestor import LocalFolderIngestor
from agent_bg_sec.monitoring.comparative_benchmark import ComparativeBenchmarkRunner


class AgentSecCLI:
    """Production terminal CLI with comprehensive subcommands and defensive exception handling."""

    def __init__(self, workspace_dir: Optional[Path] = None) -> None:
        self.workspace_dir = workspace_dir
        self.formatter = TerminalFormatter()

    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="agent-sec",
            description=(
                "AI Red Team-Driven Security Validation for Blue-Green Deployment "
                "of Autonomous AI Agents."
            ),
        )
        parser.add_argument(
            "--max-risk",
            type=float,
            default=20.0,
            help="Maximum acceptable Risk Score in %% (default: 20.0%%, meaning min Security Score is 80.0%%).",
        )
        parser.add_argument(
            "--workspace",
            type=str,
            default=None,
            help="Custom workspace directory for state, clones, and reports.",
        )
        parser.add_argument(
            "--env-file",
            type=str,
            default=None,
            help="Optional path to a custom .env file (by default loads project root .env and target agent .env).",
        )
        parser.add_argument(
            "--openrouter-key",
            type=str,
            default=None,
            help="Optional OpenRouter API key override (otherwise loaded from OPENROUTER_API_KEY in .env).",
        )
        parser.add_argument(
            "--openrouter-model",
            type=str,
            default=None,
            help="Optional OpenRouter model ID (default: meta-llama/llama-3.1-8b-instruct:free or OPENROUTER_MODEL in .env).",
        )

        subparsers = parser.add_subparsers(dest="command", help="Available operational modes")

        # 1. One-time local folder test
        folder_parser = subparsers.add_parser(
            "test-folder",
            help="One-time AI Red Team security validation of a local AI agent folder.",
        )
        folder_parser.add_argument(
            "path",
            type=str,
            help="File or folder location of the target AI agent.",
        )
        folder_parser.add_argument(
            "--no-deploy",
            action="store_true",
            help="Run validation and calculate percentage score without updating Blue-Green state.",
        )
        folder_parser.add_argument(
            "--output-json",
            type=str,
            default=None,
            help="Optional file path to save the JSON validation report.",
        )
        folder_parser.add_argument(
            "--fail-on-high-risk",
            action="store_true",
            help="Exit with non-zero code (10) if the target agent fails security validation.",
        )

        # 2. One-time GitHub repository clone & test
        github_parser = subparsers.add_parser(
            "test-github",
            help="One-time clone and AI Red Team security validation of a GitHub repository.",
        )
        github_parser.add_argument(
            "repo_url",
            type=str,
            help="GitHub repository URL (HTTPS, SSH, or local git repo path).",
        )
        github_parser.add_argument(
            "--branch",
            type=str,
            default=None,
            help="Optional branch name to clone and test.",
        )
        github_parser.add_argument(
            "--subpath",
            type=str,
            default=None,
            help="Optional subdirectory inside the repository containing the target agent.",
        )
        github_parser.add_argument(
            "--no-deploy",
            action="store_true",
            help="Run validation and calculate percentage score without updating Blue-Green state.",
        )
        github_parser.add_argument(
            "--output-json",
            type=str,
            default=None,
            help="Optional file path to save the JSON validation report.",
        )
        github_parser.add_argument(
            "--fail-on-high-risk",
            action="store_true",
            help="Exit with non-zero code (10) if the target agent fails security validation.",
        )

        # 3. Continuous GitHub watcher (automated testing on every push)
        watch_parser = subparsers.add_parser(
            "watch-github",
            help="Continuous automated testing: watches a GitHub repository for new pushes, fetches, tests in Green, scores, and promotes/rolls back.",
        )
        watch_parser.add_argument(
            "repo_url",
            type=str,
            help="GitHub repository URL to monitor for new pushes.",
        )
        watch_parser.add_argument(
            "--branch",
            type=str,
            default=None,
            help="Branch name to monitor (default: remote HEAD).",
        )
        watch_parser.add_argument(
            "--subpath",
            type=str,
            default=None,
            help="Optional subdirectory inside the repository containing the target agent.",
        )
        watch_parser.add_argument(
            "--interval",
            type=int,
            default=30,
            help="Polling interval in seconds to check for new GitHub pushes (default: 30s).",
        )
        watch_parser.add_argument(
            "--max-cycles",
            type=int,
            default=None,
            help="Optional maximum number of poll cycles to run before exiting (default: infinite).",
        )

        # 4. Blue-Green status inspection
        subparsers.add_parser(
            "status",
            help="Display current Blue (Production) and Green (Staging) deployment status and history.",
        )

        # 5. Manual emergency rollback
        rollback_parser = subparsers.add_parser(
            "rollback",
            help="Trigger an immediate rollback to the stable Blue environment.",
        )
        rollback_parser.add_argument(
            "--reason",
            type=str,
            default="Manual rollback triggered via CLI",
            help="Reason for the manual rollback.",
        )

        # 6. Experimental Comparative Evaluation Benchmark (Proposal Section 7e & C4)
        bench_parser = subparsers.add_parser(
            "benchmark",
            help="Run comparative experimental evaluation across sample AI agents (Traditional vs. Proposed Red-Team Blue-Green).",
        )
        bench_parser.add_argument(
            "--output-json",
            type=str,
            default=None,
            help="Optional path to save comparative benchmark results as JSON.",
        )

        # 7. OpenRouter configuration & live connectivity check
        subparsers.add_parser(
            "test-openrouter",
            help="Check OpenRouter configuration (.env / CLI flags) and test live LLM API connectivity.",
        )

        # 8. Explicit interactive menu command (also default when run with no arguments)
        subparsers.add_parser(
            "interactive",
            help="Launch the interactive menu-driven terminal console (default when run with no arguments).",
        )

        return parser

    def run(self, argv: Optional[List[str]] = None) -> int:
        """Parse CLI arguments and execute the requested command inside a top-level fault barrier."""
        parser = self.build_parser()
        args = parser.parse_args(argv)

        if not args.command or args.command == "interactive":
            DotEnvLoader.load_env_files()
            menu = InteractiveMenuSession(
                execute_cli_callback=self.run,
                formatter=self.formatter,
            )
            return menu.run_loop()

        try:
            extra_env = [Path(args.env_file).expanduser()] if getattr(args, "env_file", None) else None
            DotEnvLoader.load_env_files(extra_paths=extra_env)

            ws_dir = (
                Path(args.workspace).expanduser().resolve()
                if args.workspace
                else (self.workspace_dir or (Path.home() / ".agent_bg_sec"))
            )
            config = AppConfig(
                max_acceptable_risk_pct=args.max_risk,
                workspace_dir=ws_dir,
            )
            if getattr(args, "openrouter_key", None):
                config.openrouter_api_key = args.openrouter_key.strip()
            if getattr(args, "openrouter_model", None):
                config.openrouter_model = args.openrouter_model.strip()

            controller = ValidationPipelineController(
                config=config,
                formatter=self.formatter,
            )

            if args.command == "test-openrouter":
                return self._handle_test_openrouter(controller)

            if args.command == "test-folder":
                return self._handle_test_folder(args, controller)

            if args.command == "test-github":
                return self._handle_test_github(args, config, controller)

            if args.command == "watch-github":
                return self._handle_watch_github(args, config, controller)

            if args.command == "status":
                return self._handle_status(controller)

            if args.command == "rollback":
                return self._handle_rollback(args, controller)

            if args.command == "benchmark":
                return self._handle_benchmark(args, config)

            parser.print_help()
            return 0

        except AgentSecError as exc:
            print(
                self.formatter.colorize(exc.format_error(), self.formatter.RED + self.formatter.BOLD),
                file=sys.stderr,
            )
            return exc.exit_code
        except KeyboardInterrupt:
            print("\n[INFO] Execution interrupted by user.", file=sys.stderr)
            return 130
        except Exception as exc:
            # Ultimate safety net: never emit an unhandled Python traceback to production users
            print(
                self.formatter.colorize(
                    f"[CRITICAL_FAULT_BARRIER] Unexpected error caught safely: {type(exc).__name__}: {exc}",
                    self.formatter.RED + self.formatter.BOLD,
                ),
                file=sys.stderr,
            )
            return 99

    def _handle_test_folder(
        self, args: argparse.Namespace, controller: ValidationPipelineController
    ) -> int:
        ingestor = LocalFolderIngestor(args.path)
        manifest = ingestor.ingest()
        out_json = Path(args.output_json).expanduser().resolve() if args.output_json else None
        _, assessment, _ = controller.validate_and_evaluate(
            manifest=manifest,
            apply_blue_green_deployment=not args.no_deploy,
            output_json_path=out_json,
            print_report=True,
        )
        if args.fail_on_high_risk and not assessment.passed_validation:
            return 10
        return 0

    def _handle_test_github(
        self,
        args: argparse.Namespace,
        config: AppConfig,
        controller: ValidationPipelineController,
    ) -> int:
        controller.logger.info(
            f"Cloning GitHub repository '{args.repo_url}' (branch={args.branch or 'default'})..."
        )
        ingestor = GitHubRepoIngestor(
            repo_url=args.repo_url,
            clones_base_dir=config.clones_dir,
            branch=args.branch,
            subpath=args.subpath,
            clone_timeout_seconds=config.git_clone_timeout_seconds,
        )
        manifest = ingestor.ingest()
        out_json = Path(args.output_json).expanduser().resolve() if args.output_json else None
        _, assessment, _ = controller.validate_and_evaluate(
            manifest=manifest,
            apply_blue_green_deployment=not args.no_deploy,
            output_json_path=out_json,
            print_report=True,
        )
        if args.fail_on_high_risk and not assessment.passed_validation:
            return 10
        return 0

    def _handle_watch_github(
        self,
        args: argparse.Namespace,
        config: AppConfig,
        controller: ValidationPipelineController,
    ) -> int:
        if args.interval <= 0:
            raise AgentSecError(
                "Polling interval (--interval) must be a positive integer in seconds.",
                exit_code=2,
            )
        ingestor = GitHubRepoIngestor(
            repo_url=args.repo_url,
            clones_base_dir=config.clones_dir,
            branch=args.branch,
            subpath=args.subpath,
            clone_timeout_seconds=config.git_clone_timeout_seconds,
        )
        ingestor.validate_url()

        def _on_new_push(manifest: AgentManifest) -> RiskAssessment:
            _, assessment, _ = controller.validate_and_evaluate(
                manifest=manifest,
                apply_blue_green_deployment=True,
                print_report=True,
            )
            return assessment

        watcher = ContinuousGitHubWatcher(
            github_ingestor=ingestor,
            on_new_commit_callback=_on_new_push,
            logger=controller.logger,
            poll_interval_seconds=args.interval,
        )
        watcher.watch_loop(max_cycles=args.max_cycles)
        return 0

    def _handle_status(self, controller: ValidationPipelineController) -> int:
        state = controller.state_store.load_state()
        fmt = self.formatter
        print(
            fmt.banner(
                "BLUE-GREEN DEPLOYMENT CLUSTER STATUS",
                f"Active Production Traffic Slot: {state.active_traffic_slot.value} | "
                f"Total Promotions: {state.total_promotions} | Total Rollbacks: {state.total_rollbacks}",
            )
        )
        rows = [
            [
                "BLUE (Active Production)",
                state.blue_env.agent_name,
                state.blue_env.version,
                state.blue_env.commit_hash or "local",
                f"{state.blue_env.security_score_pct:.2f}%",
                f"{state.blue_env.risk_score_pct:.2f}%",
                state.blue_env.status,
                "100% LIVE" if state.blue_env.receiving_traffic else "0%",
            ]
        ]
        if state.green_env:
            rows.append(
                [
                    "GREEN (Staging Sandbox)",
                    state.green_env.agent_name,
                    state.green_env.version,
                    state.green_env.commit_hash or "local",
                    f"{state.green_env.security_score_pct:.2f}%",
                    f"{state.green_env.risk_score_pct:.2f}%",
                    state.green_env.status,
                    "100% LIVE" if state.green_env.receiving_traffic else "0% ISOLATED",
                ]
            )
        print(
            fmt.format_table(
                [
                    "Slot",
                    "Agent Name",
                    "Version",
                    "Commit",
                    "Security Score",
                    "Risk Score",
                    "Status",
                    "Traffic",
                ],
                rows,
            )
        )
        if state.history:
            print(fmt.section("Recent Blue-Green Deployment Audit History"))
            hist_rows = []
            for h in state.history[-10:]:
                hist_rows.append(
                    [
                        str(h.get("timestamp", ""))[:19],
                        str(h.get("action", "")),
                        str(h.get("agent_name") or h.get("rejected_green_agent") or h.get("active_blue_agent") or ""),
                        f"{float(h.get('security_score_pct', 100.0)):.2f}%",
                        f"{float(h.get('risk_score_pct', 0.0)):.2f}%",
                    ]
                )
            print(
                fmt.format_table(
                    ["Timestamp (UTC)", "Action", "Agent", "Security Score", "Risk Score"],
                    hist_rows,
                )
            )
        return 0

    def _handle_rollback(
        self, args: argparse.Namespace, controller: ValidationPipelineController
    ) -> int:
        _, message = controller.traffic_controller.manual_rollback(reason=args.reason)
        controller.logger.warning(message)
        return self._handle_status(controller)

    def _handle_benchmark(
        self, args: argparse.Namespace, config: AppConfig
    ) -> int:
        repo_root = Path(__file__).resolve().parents[3]
        examples_dir = repo_root / "examples"
        sample_folders = sorted(
            p for p in examples_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
        ) if examples_dir.is_dir() else []

        if not sample_folders:
            raise AgentSecError(
                f"No sample agent folders found in '{examples_dir}'.",
                recovery_hint="Ensure the examples/ directory contains sample AI agents.",
            )

        runner = ComparativeBenchmarkRunner(config=config, formatter=self.formatter)
        study = runner.run_comparative_study(sample_folders)
        print(runner.format_benchmark_report(study))

        out_path = (
            Path(args.output_json).expanduser().resolve()
            if args.output_json
            else (config.reports_dir / "comparative_benchmark_report.json")
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(study, indent=2), encoding="utf-8")
        print(f"\n[INFO] Saved comparative benchmark JSON report to: {out_path}")
        return 0

    def _handle_test_openrouter(self, controller: ValidationPipelineController) -> int:
        client = controller.openrouter_client
        fmt = self.formatter
        print(
            fmt.banner(
                "OPENROUTER LLM CONFIGURATION & CONNECTIVITY CHECK",
                f"Base URL: {client.base_url} | Model: {client.model}",
            )
        )
        masked_key = (
            f"{client.api_key[:8]}...{client.api_key[-4:]}"
            if client.is_configured and client.api_key
            else "NOT SET (Paste your key after OPENROUTER_API_KEY= in .env)"
        )
        rows = [
            ["OpenRouter Base URL", client.base_url],
            ["Configured Model", client.model],
            ["API Key Status", "CONFIGURED" if client.is_configured else "MISSING (Running in Offline AST/Sandbox Mode)"],
            ["Masked API Key", masked_key],
        ]
        print(fmt.format_table(["Setting", "Value"], rows))

        if not client.is_configured:
            controller.logger.warning(
                "OPENROUTER_API_KEY is currently empty in .env. "
                "Add your key from https://openrouter.ai/keys to enable live OpenRouter LLM attack synthesis."
            )
            return 0

        controller.logger.info(f"Sending test Red Team probe via OpenRouter model '{client.model}'...")
        resp = client.chat_completion(
            system_prompt="You are an AI security verifier.",
            user_prompt="Reply with 'OPENROUTER_ONLINE' to confirm connectivity.",
            max_tokens=32,
        )
        if resp.success:
            controller.logger.success(
                f"OpenRouter connection verified! Model '{resp.model}' responded: {resp.content}"
            )
            return 0
        controller.logger.error(f"OpenRouter request failed: {resp.error_message}")
        return 1


