"""Preflight or explicitly execute the frozen public-knowledge experiment."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

from chipchain.corpus import load_public_cve_corpus
from chipchain.evaluation import (
    AblationExperimentPlan,
    ExperimentExecutionMode,
    PHASE10D_RESPONSES_COMPLETION_CONTRACT,
    PublicKnowledgeRealExecutionPreflight,
    RealExperimentCaseInput,
    RealExperimentInputSet,
    RealModelExperimentExecutor,
    RealModelExperimentPlan,
    RealModelProviderDescriptor,
    RealModelProviderProtocol,
    load_public_knowledge_readiness,
    load_public_secondary_cohort,
    materialize_public_knowledge_execution_binding,
    real_model_provider_descriptor_id,
    strict_schema_bundle_sha256,
)
from chipchain.reasoning import LLMAPIStyle, REASONING_PROVIDER_SCHEMA_NAME


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "data/public_cve/arm_cross_layer_seed_v1.json"
DEFAULT_COHORT = (
    ROOT / "data/evaluation/public_documented_arm_secondary_v1.json"
)
DEFAULT_READINESS = (
    ROOT
    / "data/evaluation/public_documented_arm_secondary_knowledge_projection_v1.json"
)


def build_parser() -> argparse.ArgumentParser:
    """Create a deliberate two-mode public experiment parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Preflight or explicitly execute the frozen public-knowledge "
            "SECONDARY experiment."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--preflight-only",
        action="store_true",
        help="Validate all local bindings/prompts without creating a provider.",
    )
    mode.add_argument(
        "--execute-real-provider",
        action="store_true",
        help="Explicitly create the env-configured provider and execute once.",
    )
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--frozen-cohort", type=Path, default=DEFAULT_COHORT)
    parser.add_argument("--readiness", type=Path, default=DEFAULT_READINESS)
    parser.add_argument(
        "--model",
        default="public-knowledge-preflight-model",
        help="Sanitized model label used only by --preflight-only.",
    )
    parser.add_argument(
        "--api-style",
        choices=[item.value for item in LLMAPIStyle],
        default=LLMAPIStyle.CHAT_COMPLETIONS.value,
        help="Sanitized API style used only by --preflight-only.",
    )
    parser.add_argument(
        "--strict-json-schema",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Sanitized strict-schema flag used only by --preflight-only.",
    )
    parser.add_argument("--reasoning-effort")
    parser.add_argument("--max-completion-tokens", type=int)
    parser.add_argument(
        "--output",
        type=Path,
        help="Required only with --execute-real-provider.",
    )
    return parser


def _preflight_descriptor(args: argparse.Namespace) -> RealModelProviderDescriptor:
    style = LLMAPIStyle(args.api_style)
    values = {
        "provider_protocol": RealModelProviderProtocol.OPENAI_COMPATIBLE,
        "model": args.model,
        "api_style": style,
        "strict_json_schema": args.strict_json_schema,
        "reasoning_effort": args.reasoning_effort,
        "max_completion_tokens": args.max_completion_tokens,
        "schema_name": REASONING_PROVIDER_SCHEMA_NAME,
        "strict_schema_bundle_sha256": (
            strict_schema_bundle_sha256() if args.strict_json_schema else None
        ),
        "responses_completion_contract": (
            PHASE10D_RESPONSES_COMPLETION_CONTRACT
            if style is LLMAPIStyle.RESPONSES
            else None
        ),
    }
    return RealModelProviderDescriptor(
        id=real_model_provider_descriptor_id(**values),
        **values,
    )


def _build_local_execution(
    args: argparse.Namespace,
    *,
    descriptor: RealModelProviderDescriptor,
):
    cohort = load_public_secondary_cohort(args.frozen_cohort)
    readiness = load_public_knowledge_readiness(args.readiness)
    corpus = load_public_cve_corpus(args.corpus)
    manifest = cohort.benchmark_manifest
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
    materialized_by_case = {
        item.benchmark_case_id: item for item in cohort.case_materializations
    }
    case_inputs = [
        RealExperimentCaseInput.create(
            plan,
            benchmark_case_id=case.id,
            reasoning_context=materialized_by_case[case.id].reasoning_context,
            triggerability=None,
            objective_materialization=None,
            metadata={},
        )
        for case in manifest.cases
    ]
    input_set = RealExperimentInputSet.create(
        plan,
        case_inputs=case_inputs,
        metadata={},
    )
    binding = materialize_public_knowledge_execution_binding(
        experiment_plan=plan,
        frozen_cohort=cohort,
        readiness_artifact=readiness,
        corpus=corpus,
        input_set=input_set,
    )
    PublicKnowledgeRealExecutionPreflight.validate(
        experiment_plan=plan,
        manifest=manifest,
        input_set=input_set,
        binding=binding,
    )
    return plan, manifest, input_set, binding


def main(argv: Sequence[str] | None = None) -> int:
    """Run local preflight, or one explicitly opted-in provider execution."""

    args = build_parser().parse_args(argv)
    try:
        if args.preflight_only:
            descriptor = _preflight_descriptor(args)
            plan, manifest, input_set, binding = _build_local_execution(
                args,
                descriptor=descriptor,
            )
            print(f"experiment_plan_id={plan.id}")
            print(f"benchmark_manifest_id={manifest.id}")
            print(f"input_set_id={input_set.id}")
            print(f"public_knowledge_binding_id={binding.id}")
            print("expected_prompt_hashes=40")
            print("preflight=pass")
            return 0

        if args.output is None:
            print(
                "public knowledge real execution requires --output",
                file=sys.stderr,
            )
            return 2
        # Import and environment access occur only behind explicit real opt-in.
        from chipchain.reasoning.provider import (
            OpenAICompatibleReasoningProvider,
        )

        provider = OpenAICompatibleReasoningProvider.from_env()
        descriptor = RealModelProviderDescriptor.from_provider_config(
            provider.config
        )
        plan, manifest, input_set, binding = _build_local_execution(
            args,
            descriptor=descriptor,
        )
        archive = RealModelExperimentExecutor(
            provider=provider
        ).execute_with_public_knowledge(
            plan,
            manifest,
            input_set,
            public_knowledge_binding=binding,
        )
        args.output.write_text(
            archive.model_dump_json(indent=2),
            encoding="utf-8",
        )
        print(f"public_knowledge_execution_archive_id={archive.id}")
        return 0
    except Exception:
        print(
            "public knowledge experiment failed at a bounded local/execution stage",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
