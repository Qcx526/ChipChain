"""Command-line interface for ChipChain."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys

from chipchain import __version__


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser."""

    parser = argparse.ArgumentParser(
        prog="chipchain",
        description=(
            "Evidence-guided detection and verification of cross-layer chip "
            "vulnerability chains."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="command")
    experiment = commands.add_parser(
        "experiment", help="Run explicitly selected experiment workflows."
    )
    experiment_commands = experiment.add_subparsers(
        dest="experiment_command"
    )
    real_model = experiment_commands.add_parser(
        "real-model",
        help="Execute the opt-in Phase 10D real-model harness.",
    )
    real_model.add_argument("--manifest", required=True)
    real_model.add_argument("--inputs", required=True)
    real_model.add_argument("--output", required=True)
    real_model.add_argument(
        "--execute-real-provider",
        action="store_true",
        help="Explicitly permit provider creation and planned model requests.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ChipChain CLI and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "experiment" and args.experiment_command == "real-model":
        if not args.execute_real_provider:
            print(
                "chipchain: real-model execution requires explicit "
                "--execute-real-provider opt-in",
                file=sys.stderr,
            )
            return 2
        return _run_real_model_experiment(args)
    return 0


def _run_real_model_experiment(args: argparse.Namespace) -> int:
    """Create provider state only after the CLI opt-in gate has passed."""

    try:
        from chipchain.agents import ReasoningContext
        from chipchain.evaluation import (
            AblationExperimentPlan,
            ExperimentExecutionMode,
            RealExperimentCaseInput,
            RealExperimentInputSet,
            RealModelExperimentExecutor,
            RealModelExperimentPlan,
            RealModelProviderDescriptor,
        )
        from chipchain.evaluation.models import BenchmarkManifest
        from chipchain.hardware_trigger.aggregation import (
            TriggerabilityAggregationResult,
        )
        from chipchain.reasoning.provider import (
            OpenAICompatibleReasoningProvider,
        )

        manifest_payload = json.loads(
            Path(args.manifest).read_text(encoding="utf-8")
        )
        _validate_cli_input_payload(manifest_payload)
        manifest = BenchmarkManifest.model_validate(manifest_payload)
        input_payload = json.loads(
            Path(args.inputs).read_text(encoding="utf-8")
        )
        _validate_cli_input_payload(input_payload)
        if not isinstance(input_payload, dict):
            raise ValueError("execution input payload must be an object")
        raw_cases = input_payload.get("case_inputs")
        if not isinstance(raw_cases, list):
            raise ValueError("execution input payload requires case_inputs")
        if set(input_payload).difference({"case_inputs", "metadata"}):
            raise ValueError("execution input payload contains unknown fields")
        parsed_cases = []
        for raw_case in raw_cases:
            if not isinstance(raw_case, dict):
                raise ValueError("execution case input must be an object")
            if set(raw_case).difference(
                {
                    "benchmark_case_id",
                    "reasoning_context",
                    "triggerability",
                    "metadata",
                }
            ):
                raise ValueError("execution case input contains unknown fields")
            context = ReasoningContext.model_validate(
                raw_case["reasoning_context"]
            )
            raw_trigger = raw_case.get("triggerability")
            trigger = (
                TriggerabilityAggregationResult.model_validate(raw_trigger)
                if raw_trigger is not None
                else None
            )
            parsed_cases.append(
                (
                    str(raw_case["benchmark_case_id"]),
                    context,
                    trigger,
                    raw_case.get("metadata") or {},
                )
            )
        manifest_cases = {item.id: item for item in manifest.cases}
        parsed_case_ids = [item[0] for item in parsed_cases]
        if (
            len(parsed_case_ids) != len(set(parsed_case_ids))
            or set(parsed_case_ids) != set(manifest_cases)
        ):
            raise ValueError("execution input cases must exactly match manifest")
        if any(
            context.architecture
            is not manifest_cases[case_id].architecture
            for case_id, context, _, _ in parsed_cases
        ):
            raise ValueError("execution context architecture mismatch")

        provider = OpenAICompatibleReasoningProvider.from_env()
        descriptor = RealModelProviderDescriptor.from_provider_config(
            provider.config
        )
        ablation_plan = AblationExperimentPlan.create(
            benchmark_manifest_id=manifest.id,
            benchmark_version=manifest.benchmark_version,
        )
        plan = RealModelExperimentPlan.create(
            manifest=manifest,
            ablation_plan=ablation_plan,
            provider_descriptor=descriptor,
            execution_mode=ExperimentExecutionMode.REAL_PROVIDER,
        )
        case_inputs = []
        for case_id, context, trigger, metadata in parsed_cases:
            case_inputs.append(
                RealExperimentCaseInput.create(
                    plan,
                    benchmark_case_id=case_id,
                    reasoning_context=context,
                    triggerability=trigger,
                    metadata=metadata,
                )
            )
        input_set = RealExperimentInputSet.create(
            plan,
            case_inputs=case_inputs,
            metadata=input_payload.get("metadata") or {},
        )
        archive = RealModelExperimentExecutor(provider=provider).execute(
            plan, manifest, input_set
        )
        Path(args.output).write_text(
            archive.model_dump_json(indent=2), encoding="utf-8"
        )
        artifact = archive.experiment_artifact
        print(f"execution_archive_id={archive.id}")
        print(f"experiment_artifact_id={artifact.id}")
        print(f"execution_mode={plan.execution_mode.value}")
        print(f"execution_complete={str(artifact.execution_complete).lower()}")
        print(
            "prompt_visibility_valid="
            f"{str(artifact.prompt_visibility_valid).lower()}"
        )
        return 0
    except Exception:
        print(
            "chipchain: real-model experiment failed at a bounded execution stage",
            file=sys.stderr,
        )
        return 1


def _validate_cli_input_payload(value: object) -> None:
    """Reject secret/transport fields before provider creation or execution."""

    forbidden = {
        "apikey",
        "authorization",
        "baseurl",
        "endpoint",
        "groundtruth",
        "password",
        "provideroutput",
        "rawprompt",
        "rawresponse",
        "secret",
        "token",
    }

    def visit(item: object) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                normalized = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if normalized in forbidden:
                    raise ValueError(
                        "execution input contains forbidden transport state"
                    )
                visit(nested)
        elif isinstance(item, list):
            for nested in item:
                visit(nested)

    visit(value)
