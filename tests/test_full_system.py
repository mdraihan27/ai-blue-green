"""Comprehensive unit and integration test suite for the AI Red Team & Blue-Green Deployment application."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_bg_sec.cli.app import AgentSecCLI
from agent_bg_sec.cli.interactive_menu import InteractiveMenuSession
from agent_bg_sec.core.config import AppConfig, MetricWeights
from agent_bg_sec.core.exceptions import (
    ConfigurationError,
    GitOperationError,
    IngestionError,
    IntrospectionError,
)
from agent_bg_sec.core.logger import AuditLogger
from agent_bg_sec.core.models import DeploymentDecisionType, DeploymentSlot
from agent_bg_sec.core.openrouter_client import OpenRouterClient
from agent_bg_sec.deployment.state_store import BlueGreenStateStore
from agent_bg_sec.deployment.traffic_router import BlueGreenTrafficController
from agent_bg_sec.evaluation.risk_scorer import SecurityRiskScorer
from agent_bg_sec.ingestion.continuous_watcher import ContinuousGitHubWatcher
from agent_bg_sec.ingestion.github_ingestor import GitHubRepoIngestor
from agent_bg_sec.ingestion.local_folder_ingestor import LocalFolderIngestor
from agent_bg_sec.redteam.orchestrator import RedTeamOrchestrator


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"


class TestCoreConfigAndExceptions(unittest.TestCase):
    """Tests configuration validation and custom exception handling."""

    def test_metric_weights_must_sum_to_one(self) -> None:
        with self.assertRaises(ConfigurationError):
            MetricWeights(
                asr_weight=0.5,
                pvr_weight=0.5,
                tmr_weight=0.5,
                sdlr_weight=0.1,
                tcs_weight=0.05,
                rt_weight=0.05,
            ).validate()

    def test_negative_weights_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            MetricWeights(
                asr_weight=-0.1,
                pvr_weight=0.3,
                tmr_weight=0.3,
                sdlr_weight=0.3,
                tcs_weight=0.1,
                rt_weight=0.1,
            ).validate()

    def test_invalid_risk_threshold_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            AppConfig(max_acceptable_risk_pct=125.0)


class TestLocalFolderIngestorAndEdgeCases(unittest.TestCase):
    """Tests local folder ingestion, file resolution, and edge-case error handling."""

    def test_empty_path_raises_ingestion_error(self) -> None:
        ingestor = LocalFolderIngestor("   ")
        with self.assertRaises(IngestionError):
            ingestor.ingest()

    def test_nonexistent_path_raises_ingestion_error(self) -> None:
        ingestor = LocalFolderIngestor("/nonexistent/path/to/agent_xyz_999")
        with self.assertRaises(IngestionError):
            ingestor.ingest()

    def test_empty_directory_raises_ingestion_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ingestor = LocalFolderIngestor(tmp)
            with self.assertRaises(IngestionError):
                ingestor.ingest()

    def test_directory_without_python_or_manifest_raises_introspection_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "notes.txt").write_text("just text", encoding="utf-8")
            ingestor = LocalFolderIngestor(tmp)
            with self.assertRaises(IntrospectionError):
                ingestor.ingest()

    def test_malformed_manifest_json_raises_introspection_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "agent_manifest.json").write_text("{bad json", encoding="utf-8")
            ingestor = LocalFolderIngestor(tmp)
            with self.assertRaises(IntrospectionError):
                ingestor.ingest()

    def test_syntax_error_in_target_python_file_handled_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "broken.py").write_text("def broken(:\n  pass", encoding="utf-8")
            manifest = LocalFolderIngestor(tmp).ingest()
            self.assertEqual(manifest.agent_name, Path(tmp).name)
            self.assertGreaterEqual(len(manifest.tools), 1)

    def test_single_python_file_path_resolves_parent_folder(self) -> None:
        agent_file = EXAMPLES_DIR / "safe_banking_agent" / "agent.py"
        manifest = LocalFolderIngestor(agent_file).ingest()
        self.assertEqual(manifest.agent_name, "safe_banking_agent")
        self.assertTrue(manifest.security_profile.has_prompt_guard)


class TestRedTeamScoringAndBlueGreenLifecycle(unittest.TestCase):
    """Tests Red Team execution, percentage scoring, promotion, and auto-rollback."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config = AppConfig(
            max_acceptable_risk_pct=20.0,
            workspace_dir=Path(self.tmp_dir.name),
        )
        self.config.ensure_directories()
        self.orchestrator = RedTeamOrchestrator()
        self.scorer = SecurityRiskScorer(self.config)
        self.state_store = BlueGreenStateStore(self.config.state_file_path)
        self.router = BlueGreenTrafficController(self.state_store)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_safe_banking_agent_scores_100_percent_and_promotes_to_blue(self) -> None:
        manifest = LocalFolderIngestor(EXAMPLES_DIR / "safe_banking_agent").ingest()
        report = self.orchestrator.run_validation_suite(manifest)
        assessment = self.scorer.evaluate(report)

        self.assertEqual(assessment.security_score_pct, 100.0)
        self.assertEqual(assessment.risk_score_pct, 0.0)
        self.assertTrue(assessment.passed_validation)
        self.assertEqual(assessment.decision, DeploymentDecisionType.PROMOTE_TO_BLUE)

        state, _ = self.router.apply_deployment_decision(manifest, assessment)
        self.assertEqual(state.blue_env.agent_name, "safe_banking_agent")
        self.assertEqual(state.total_promotions, 1)
        self.assertEqual(state.total_rollbacks, 0)

    def test_vulnerable_devops_agent_fails_and_triggers_auto_rollback(self) -> None:
        # First promote safe_banking_agent to Blue
        safe_manifest = LocalFolderIngestor(EXAMPLES_DIR / "safe_banking_agent").ingest()
        safe_report = self.orchestrator.run_validation_suite(safe_manifest)
        safe_assessment = self.scorer.evaluate(safe_report)
        self.router.apply_deployment_decision(safe_manifest, safe_assessment)

        # Now test vulnerable_devops_agent in Green
        vuln_manifest = LocalFolderIngestor(EXAMPLES_DIR / "vulnerable_devops_agent").ingest()
        vuln_report = self.orchestrator.run_validation_suite(vuln_manifest)
        vuln_assessment = self.scorer.evaluate(vuln_report)

        self.assertFalse(vuln_assessment.passed_validation)
        self.assertLess(vuln_assessment.security_score_pct, 30.0)
        self.assertGreater(vuln_assessment.risk_score_pct, 70.0)
        self.assertEqual(vuln_assessment.decision, DeploymentDecisionType.ROLLBACK_TO_BLUE)

        state, summary = self.router.apply_deployment_decision(vuln_manifest, vuln_assessment)
        self.assertIn("AUTO-ROLLBACK TRIGGERED", summary)
        # Active Blue environment must still be safe_banking_agent!
        self.assertEqual(state.blue_env.agent_name, "safe_banking_agent")
        self.assertTrue(state.blue_env.receiving_traffic)
        self.assertIsNotNone(state.green_env)
        self.assertFalse(state.green_env.receiving_traffic)
        self.assertEqual(state.total_rollbacks, 1)


class TestGitHubCloneAndContinuousPushWatcher(unittest.TestCase):
    """Tests one-time Git repository clone & test plus continuous push polling."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.tmp_dir.name)
        self.remote_repo = self.base_path / "mock_github_repo"
        self.remote_repo.mkdir(parents=True, exist_ok=True)
        self.workspace_dir = self.base_path / "workspace"

        # Initialize a real git repository simulating a remote GitHub repo
        subprocess.run(["git", "init", str(self.remote_repo)], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(self.remote_repo), "config", "user.email", "test@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.remote_repo), "config", "user.name", "Tester"],
            check=True,
        )

        # Commit 1: Safe agent
        for f in (EXAMPLES_DIR / "safe_banking_agent").iterdir():
            if f.is_file():
                (self.remote_repo / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
        subprocess.run(["git", "-C", str(self.remote_repo), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.remote_repo), "commit", "-m", "Initial safe agent commit"],
            check=True,
            capture_output=True,
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_invalid_github_url_rejected(self) -> None:
        ingestor = GitHubRepoIngestor(
            repo_url="http://not-github.example.org/malicious/repo",
            clones_base_dir=self.workspace_dir / "clones",
        )
        with self.assertRaises(GitOperationError):
            ingestor.validate_url()

    def test_one_time_github_clone_and_score(self) -> None:
        cli = AgentSecCLI(workspace_dir=self.workspace_dir)
        out_json = self.workspace_dir / "gh_one_time.json"
        exit_code = cli.run(
            [
                "--workspace",
                str(self.workspace_dir),
                "test-github",
                str(self.remote_repo),
                "--output-json",
                str(out_json),
            ]
        )
        self.assertEqual(exit_code, 0)
        self.assertTrue(out_json.is_file())
        data = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(data["risk_assessment"]["security_score_pct"], 100.0)

    def test_continuous_watcher_detects_new_push_and_rolls_back_vulnerable_commit(self) -> None:
        config = AppConfig(workspace_dir=self.workspace_dir)
        config.ensure_directories()
        ingestor = GitHubRepoIngestor(
            repo_url=str(self.remote_repo),
            clones_base_dir=config.clones_dir,
        )
        orchestrator = RedTeamOrchestrator()
        scorer = SecurityRiskScorer(config)
        state_store = BlueGreenStateStore(config.state_file_path)
        router = BlueGreenTrafficController(state_store)
        logger = AuditLogger(quiet=True)

        def callback(manifest):
            rep = orchestrator.run_validation_suite(manifest)
            assess = scorer.evaluate(rep)
            router.apply_deployment_decision(manifest, assess)
            return assess

        watcher = ContinuousGitHubWatcher(
            github_ingestor=ingestor,
            on_new_commit_callback=callback,
            logger=logger,
            poll_interval_seconds=1,
        )

        # Cycle 1: Initial commit detected -> Tested -> 100% score -> Promoted to Blue
        ev1 = watcher.check_once(cycle_number=1, force_initial=True)
        self.assertTrue(ev1.triggered_test)
        self.assertEqual(ev1.security_score_pct, 100.0)

        # Cycle 2: No new push -> Should not trigger duplicate test
        ev2 = watcher.check_once(cycle_number=2, force_initial=False)
        self.assertFalse(ev2.triggered_test)

        # Simulate a new GitHub push introducing a vulnerable agent change
        for f in (EXAMPLES_DIR / "vulnerable_devops_agent").iterdir():
            if f.is_file():
                (self.remote_repo / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
        subprocess.run(["git", "-C", str(self.remote_repo), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.remote_repo), "commit", "-m", "Push vulnerable agent update"],
            check=True,
            capture_output=True,
        )

        # Cycle 3: Watcher detects new commit SHA -> Automatically fetches, tests, scores, and rolls back!
        ev3 = watcher.check_once(cycle_number=3, force_initial=False)
        self.assertTrue(ev3.triggered_test)
        self.assertNotEqual(ev3.detected_commit, ev1.detected_commit)
        self.assertLess(ev3.security_score_pct, 30.0)
        self.assertEqual(ev3.decision, DeploymentDecisionType.ROLLBACK_TO_BLUE.value)

        # Verify Blue environment is still safely serving safe_banking_agent
        final_state = state_store.load_state()
        self.assertEqual(final_state.blue_env.agent_name, "safe_banking_agent")
        self.assertEqual(final_state.total_promotions, 1)
        self.assertEqual(final_state.total_rollbacks, 1)


class TestCLISubcommandsEndToEnd(unittest.TestCase):
    """Tests all CLI subcommands (`test-folder`, `status`, `rollback`, `benchmark`)."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp_dir.name)
        self.cli = AgentSecCLI(workspace_dir=self.ws)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_cli_full_workflow(self) -> None:
        # 1. Test safe folder
        code1 = self.cli.run(
            ["--workspace", str(self.ws), "test-folder", str(EXAMPLES_DIR / "safe_banking_agent")]
        )
        self.assertEqual(code1, 0)

        # 2. Test vulnerable folder with --fail-on-high-risk (should return exit code 10)
        code2 = self.cli.run(
            [
                "--workspace",
                str(self.ws),
                "test-folder",
                str(EXAMPLES_DIR / "vulnerable_devops_agent"),
                "--fail-on-high-risk",
            ]
        )
        self.assertEqual(code2, 10)

        # 3. Check status
        code3 = self.cli.run(["--workspace", str(self.ws), "status"])
        self.assertEqual(code3, 0)

        # 4. Manual rollback
        code4 = self.cli.run(
            ["--workspace", str(self.ws), "rollback", "--reason", "Routine drill"]
        )
        self.assertEqual(code4, 0)

        # 5. Comparative Benchmark
        bench_json = self.ws / "bench.json"
        code5 = self.cli.run(
            ["--workspace", str(self.ws), "benchmark", "--output-json", str(bench_json)]
        )
        self.assertEqual(code5, 0)
        self.assertTrue(bench_json.is_file())

        # 6. OpenRouter status & config check
        code6 = self.cli.run(["--workspace", str(self.ws), "test-openrouter"])
        self.assertEqual(code6, 0)

    def test_openrouter_client_fallback_when_unconfigured(self) -> None:
        client = OpenRouterClient(api_key="", model="meta-llama/llama-3.1-8b-instruct:free")
        self.assertFalse(client.is_configured)
        synthesized = client.synthesize_contextual_attack(
            agent_name="test_agent",
            domain="finance",
            category_name="prompt_injection",
            tool_names=["transfer_funds"],
            fallback_prompt="BASE_FALLBACK_PROMPT",
        )
        self.assertEqual(synthesized, "BASE_FALLBACK_PROMPT")

    def test_interactive_menu_navigation(self) -> None:
        inputs = iter(["4", "1", "q"])
        menu = InteractiveMenuSession(
            execute_cli_callback=lambda argv: self.cli.run(["--workspace", str(self.ws)] + argv),
            input_fn=lambda _prompt: next(inputs, "0"),
        )
        exit_code = menu.run_loop()
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
