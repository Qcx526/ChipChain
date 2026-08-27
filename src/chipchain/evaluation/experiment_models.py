"""Phase 10D Step 1 provider, plan, invocation, and failure contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from pydantic import Field, field_validator, model_validator

from chipchain.evaluation.ablation_models import (
    PHASE10C_ABLATION_CONTRACT,
    AblationConditionSpec,
    AblationExperimentPlan,
    ablation_experiment_plan_id,
    structured_prompt_sha256,
)
from chipchain.evaluation.enums import (
    AblationConditionKind,
    ExperimentExecutionMode,
    ModelInvocationDisposition,
    RealModelInvocationFailureCode,
    RealModelInvocationFailureStage,
    RealModelProviderProtocol,
    StructuredParseFailureDetail,
)
from chipchain.evaluation.feasibility_models import _validate_failure_metadata
from chipchain.evaluation.models import BenchmarkManifest, _canonical_hash
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.reasoning.enums import LLMAPIStyle, ReasoningAgentType
from chipchain.reasoning.models import (
    LLMProviderConfig,
    REASONING_PROVIDER_SCHEMA_NAME,
    StructuredPromptRequest,
)
from chipchain.reasoning.parser import (
    reasoning_provider_output_json_schema_for_role,
)


PHASE10D_EXPERIMENT_CONTRACT = "phase10d_real_model_experiment_v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HTTP_URL = re.compile(r"(?i)\bhttps?://\S+")
_FORBIDDEN_EXPERIMENT_METADATA_FRAGMENTS = (
    "baseurl",
    "endpoint",
    "errorrepr",
    "exception",
    "proxy",
    "rawprompt",
    "rawresponse",
    "systemprompt",
    "userprompt",
)
_MODEL_CONDITIONS = frozenset(
    {
        AblationConditionKind.FULL_CONTEXT_MODEL,
        AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
    }
)
PHASE10D_PROVIDER_ROLE_ORDER = (
    ReasoningAgentType.CODE,
    ReasoningAgentType.HARDWARE,
    ReasoningAgentType.VULNERABILITY,
    ReasoningAgentType.ATTACK_CHAIN,
)
"""Frozen provider-backed role order mirrored by the Phase 10D v1 matrix."""
_PHASE10D_PROVIDER_ROLES = frozenset(PHASE10D_PROVIDER_ROLE_ORDER)


def _unique_sorted(values: list[str], label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return sorted(values)


def _validate_sha256(value: str, label: str) -> str:
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _validate_experiment_metadata(metadata: Metadata) -> Metadata:
    """Reject transport content and locations in Phase 10D metadata."""

    _validate_failure_metadata(metadata)

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if any(
                    fragment in normalized
                    for fragment in _FORBIDDEN_EXPERIMENT_METADATA_FRAGMENTS
                ):
                    raise ValueError(
                        "experiment metadata contains forbidden transport content"
                    )
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)
        elif isinstance(value, str) and _HTTP_URL.search(value):
            raise ValueError("experiment metadata must not contain provider URLs")

    visit(metadata)
    return metadata


def strict_schema_bundle_sha256(
    schemas_by_role: Mapping[
        ReasoningAgentType | str, dict[str, object]
    ]
    | None = None,
) -> str:
    """Hash the exact four role-aware schemas with stable JSON canonicalization."""

    source = (
        schemas_by_role
        if schemas_by_role is not None
        else {
            role: reasoning_provider_output_json_schema_for_role(role)
            for role in PHASE10D_PROVIDER_ROLE_ORDER
        }
    )
    normalized: dict[str, dict[str, object]] = {}
    for raw_role, schema in source.items():
        role = ReasoningAgentType(raw_role)
        if role not in _PHASE10D_PROVIDER_ROLES:
            raise ValueError("schema bundle contains unsupported provider role")
        if role.value in normalized:
            raise ValueError("schema bundle provider roles must be unique")
        if not isinstance(schema, dict):
            raise TypeError("schema bundle entries must be JSON schema objects")
        normalized[role.value] = schema
    if set(normalized) != {role.value for role in PHASE10D_PROVIDER_ROLE_ORDER}:
        raise ValueError("schema bundle requires exactly four provider roles")
    canonical = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def real_model_provider_descriptor_id(
    *,
    provider_protocol: RealModelProviderProtocol,
    model: str,
    api_style: LLMAPIStyle,
    strict_json_schema: bool,
    reasoning_effort: str | None,
    max_completion_tokens: int | None,
    schema_name: str,
    strict_schema_bundle_sha256: str | None = None,
) -> str:
    """Bind only non-secret model-semantic experiment configuration."""

    payload = {
        "api_style": LLMAPIStyle(api_style).value,
        "max_completion_tokens": max_completion_tokens,
        "model": model,
        "provider_protocol": RealModelProviderProtocol(provider_protocol).value,
        "reasoning_effort": reasoning_effort,
        "schema_name": schema_name,
        "strict_json_schema": strict_json_schema,
    }
    if strict_schema_bundle_sha256 is not None:
        payload["strict_schema_bundle_sha256"] = _validate_sha256(
            strict_schema_bundle_sha256, "strict schema bundle hash"
        )
    return _canonical_hash("real-model-provider-descriptor", payload)


class RealModelProviderDescriptor(DomainModel):
    """Sanitized model configuration with no endpoint or secret fields."""

    id: Identifier
    provider_protocol: RealModelProviderProtocol
    model: Identifier
    api_style: LLMAPIStyle
    strict_json_schema: bool
    reasoning_effort: Identifier | None = None
    max_completion_tokens: int | None = Field(default=None, gt=0)
    schema_name: Identifier
    strict_schema_bundle_sha256: str | None = None

    @field_validator("reasoning_effort")
    @classmethod
    def validate_reasoning_effort(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in {
            "none",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh",
            "max",
        }:
            raise ValueError("unsupported experiment reasoning effort")
        return normalized

    @field_validator("strict_schema_bundle_sha256")
    @classmethod
    def validate_schema_bundle_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_sha256(value, "strict schema bundle hash")

    @model_validator(mode="after")
    def validate_identity(self) -> "RealModelProviderDescriptor":
        expected = real_model_provider_descriptor_id(
            provider_protocol=self.provider_protocol,
            model=self.model,
            api_style=self.api_style,
            strict_json_schema=self.strict_json_schema,
            reasoning_effort=self.reasoning_effort,
            max_completion_tokens=self.max_completion_tokens,
            schema_name=self.schema_name,
            strict_schema_bundle_sha256=self.strict_schema_bundle_sha256,
        )
        if (
            not self.strict_json_schema
            and self.strict_schema_bundle_sha256 is not None
        ):
            raise ValueError(
                "non-strict provider descriptor cannot bind a schema bundle"
            )
        if self.id != expected:
            raise ValueError("RealModelProviderDescriptor ID is not deterministic")
        return self

    @classmethod
    def from_provider_config(
        cls,
        config: LLMProviderConfig,
        *,
        schema_name: str = REASONING_PROVIDER_SCHEMA_NAME,
    ) -> "RealModelProviderDescriptor":
        """Omit base URL, timeout, and all execution-only secret state."""

        if not isinstance(config, LLMProviderConfig):
            raise TypeError("provider descriptor requires LLMProviderConfig")
        snapshot = LLMProviderConfig.model_validate(config.model_dump(mode="json"))
        values = {
            "provider_protocol": RealModelProviderProtocol.OPENAI_COMPATIBLE,
            "model": snapshot.model,
            "api_style": snapshot.api_style,
            "strict_json_schema": snapshot.json_mode,
            "reasoning_effort": snapshot.reasoning_effort,
            "max_completion_tokens": snapshot.max_completion_tokens,
            "schema_name": schema_name.strip(),
            "strict_schema_bundle_sha256": (
                strict_schema_bundle_sha256() if snapshot.json_mode else None
            ),
        }
        return cls(
            id=real_model_provider_descriptor_id(**values),
            **values,
        )


def real_model_experiment_plan_id(
    *,
    contract: str,
    benchmark_manifest_id: str,
    benchmark_version: str,
    ablation_plan_id: str,
    provider_descriptor_id: str,
    execution_mode: ExperimentExecutionMode,
    condition_spec_ids: list[str],
    case_ids: list[str],
    provider_role_order: list[ReasoningAgentType],
) -> str:
    """Build one frozen experiment matrix identity before outputs exist."""

    return _canonical_hash(
        "real-model-experiment-plan",
        {
            "ablation_plan_id": ablation_plan_id,
            "benchmark_manifest_id": benchmark_manifest_id,
            "benchmark_version": benchmark_version,
            "case_ids": sorted(case_ids),
            "condition_spec_ids": sorted(condition_spec_ids),
            "contract": contract,
            "execution_mode": ExperimentExecutionMode(execution_mode).value,
            "provider_descriptor_id": provider_descriptor_id,
            "provider_role_order": [
                ReasoningAgentType(role).value for role in provider_role_order
            ],
        },
    )


class RealModelExperimentPlan(DomainModel):
    """Frozen same-model four-condition matrix declared before any output."""

    id: Identifier
    contract: Identifier
    benchmark_manifest_id: Identifier
    benchmark_version: Identifier
    ablation_plan_id: Identifier
    ablation_primary_model_condition: AblationConditionKind
    provider_descriptor: RealModelProviderDescriptor
    execution_mode: ExperimentExecutionMode
    condition_specs: list[AblationConditionSpec]
    case_ids: list[Identifier] = Field(min_length=1)
    provider_role_order: list[ReasoningAgentType]
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("condition_specs")
    @classmethod
    def normalize_condition_specs(
        cls, values: list[AblationConditionSpec]
    ) -> list[AblationConditionSpec]:
        if len(values) != len(AblationConditionKind) or {
            item.condition_kind for item in values
        } != set(AblationConditionKind):
            raise ValueError("experiment plan requires all four ablation conditions")
        if any(item.repetitions != 1 for item in values):
            raise ValueError("Phase 10D v1 requires one repetition")
        return sorted(values, key=lambda item: item.condition_kind.value)

    @field_validator("case_ids")
    @classmethod
    def normalize_case_ids(cls, values: list[str]) -> list[str]:
        return _unique_sorted(values, "experiment benchmark case IDs")

    @field_validator("provider_role_order")
    @classmethod
    def validate_provider_role_order(
        cls, values: list[ReasoningAgentType]
    ) -> list[ReasoningAgentType]:
        if tuple(values) != PHASE10D_PROVIDER_ROLE_ORDER:
            raise ValueError("experiment plan requires fixed provider role order")
        return list(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_experiment_metadata(value)

    @model_validator(mode="after")
    def validate_contract_and_identity(self) -> "RealModelExperimentPlan":
        if self.contract != PHASE10D_EXPERIMENT_CONTRACT:
            raise ValueError("unsupported real-model experiment contract")
        if self.provider_descriptor.schema_name != REASONING_PROVIDER_SCHEMA_NAME:
            raise ValueError("experiment plan requires current reasoning schema")
        expected_ablation_id = ablation_experiment_plan_id(
            contract=PHASE10C_ABLATION_CONTRACT,
            benchmark_manifest_id=self.benchmark_manifest_id,
            benchmark_version=self.benchmark_version,
            condition_spec_ids=[item.id for item in self.condition_specs],
            primary_model_condition=self.ablation_primary_model_condition,
        )
        if self.ablation_plan_id != expected_ablation_id:
            raise ValueError("experiment and ablation plan binding mismatch")
        expected = real_model_experiment_plan_id(
            contract=self.contract,
            benchmark_manifest_id=self.benchmark_manifest_id,
            benchmark_version=self.benchmark_version,
            ablation_plan_id=self.ablation_plan_id,
            provider_descriptor_id=self.provider_descriptor.id,
            execution_mode=self.execution_mode,
            condition_spec_ids=[item.id for item in self.condition_specs],
            case_ids=self.case_ids,
            provider_role_order=self.provider_role_order,
        )
        if self.id != expected:
            raise ValueError("RealModelExperimentPlan ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        manifest: BenchmarkManifest,
        ablation_plan: AblationExperimentPlan,
        provider_descriptor: RealModelProviderDescriptor,
        execution_mode: ExperimentExecutionMode | str,
        metadata: Metadata | None = None,
    ) -> "RealModelExperimentPlan":
        """Freeze one manifest and the accepted Phase 10C plan before outputs."""

        if not isinstance(manifest, BenchmarkManifest):
            raise TypeError("experiment plan requires BenchmarkManifest")
        if not isinstance(ablation_plan, AblationExperimentPlan):
            raise TypeError("experiment plan requires AblationExperimentPlan")
        if not isinstance(provider_descriptor, RealModelProviderDescriptor):
            raise TypeError("experiment plan requires RealModelProviderDescriptor")
        manifest_snapshot = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json")
        )
        ablation_snapshot = AblationExperimentPlan.model_validate(
            ablation_plan.model_dump(mode="json")
        )
        descriptor_snapshot = RealModelProviderDescriptor.model_validate(
            provider_descriptor.model_dump(mode="json")
        )
        if (
            ablation_snapshot.benchmark_manifest_id,
            ablation_snapshot.benchmark_version,
        ) != (manifest_snapshot.id, manifest_snapshot.benchmark_version):
            raise ValueError("experiment requires ablation plan for frozen manifest")
        mode = ExperimentExecutionMode(execution_mode)
        if (
            mode is ExperimentExecutionMode.REAL_PROVIDER
            and descriptor_snapshot.strict_json_schema
            and descriptor_snapshot.strict_schema_bundle_sha256 is None
        ):
            raise ValueError(
                "REAL_PROVIDER strict schema requires bundle provenance"
            )
        specs = list(ablation_snapshot.condition_specs)
        cases = [item.id for item in manifest_snapshot.cases]
        identity = real_model_experiment_plan_id(
            contract=PHASE10D_EXPERIMENT_CONTRACT,
            benchmark_manifest_id=manifest_snapshot.id,
            benchmark_version=manifest_snapshot.benchmark_version,
            ablation_plan_id=ablation_snapshot.id,
            provider_descriptor_id=descriptor_snapshot.id,
            execution_mode=mode,
            condition_spec_ids=[item.id for item in specs],
            case_ids=cases,
            provider_role_order=list(PHASE10D_PROVIDER_ROLE_ORDER),
        )
        return cls(
            id=identity,
            contract=PHASE10D_EXPERIMENT_CONTRACT,
            benchmark_manifest_id=manifest_snapshot.id,
            benchmark_version=manifest_snapshot.benchmark_version,
            ablation_plan_id=ablation_snapshot.id,
            ablation_primary_model_condition=(
                ablation_snapshot.primary_model_condition
            ),
            provider_descriptor=descriptor_snapshot,
            execution_mode=mode,
            condition_specs=specs,
            case_ids=cases,
            provider_role_order=list(PHASE10D_PROVIDER_ROLE_ORDER),
            metadata=metadata or {},
        )


def experiment_case_invocation_key_id(
    *,
    experiment_plan_id: str,
    condition_kind: AblationConditionKind,
    benchmark_case_id: str,
    role: ReasoningAgentType,
    repetition_index: int,
) -> str:
    """Bind one model-backed condition/case/role/repetition execution slot."""

    return _canonical_hash(
        "experiment-case-invocation-key",
        {
            "benchmark_case_id": benchmark_case_id,
            "condition_kind": AblationConditionKind(condition_kind).value,
            "experiment_plan_id": experiment_plan_id,
            "role": ReasoningAgentType(role).value,
            "repetition_index": repetition_index,
        },
    )


class ExperimentCaseInvocationKey(DomainModel):
    """Deterministic key for one provider role attempt in one v1 case."""

    id: Identifier
    experiment_plan_id: Identifier
    condition_kind: AblationConditionKind
    benchmark_case_id: Identifier
    role: ReasoningAgentType
    repetition_index: int = Field(ge=0, le=0)

    @model_validator(mode="after")
    def validate_scope_and_identity(self) -> "ExperimentCaseInvocationKey":
        if self.condition_kind not in _MODEL_CONDITIONS:
            raise ValueError("only FULL/MASKED conditions have model invocations")
        if self.role not in _PHASE10D_PROVIDER_ROLES:
            raise ValueError("unsupported Phase 10D provider role")
        expected = experiment_case_invocation_key_id(
            experiment_plan_id=self.experiment_plan_id,
            condition_kind=self.condition_kind,
            benchmark_case_id=self.benchmark_case_id,
            role=self.role,
            repetition_index=self.repetition_index,
        )
        if self.id != expected:
            raise ValueError("ExperimentCaseInvocationKey ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        plan: RealModelExperimentPlan,
        *,
        condition_kind: AblationConditionKind | str,
        benchmark_case_id: str,
        role: ReasoningAgentType | str,
        repetition_index: int = 0,
    ) -> "ExperimentCaseInvocationKey":
        if not isinstance(plan, RealModelExperimentPlan):
            raise TypeError("invocation key requires RealModelExperimentPlan")
        condition = AblationConditionKind(condition_kind)
        normalized_role = ReasoningAgentType(role)
        case_id = benchmark_case_id.strip()
        if case_id not in plan.case_ids:
            raise ValueError("invocation case is not in frozen experiment plan")
        identity = experiment_case_invocation_key_id(
            experiment_plan_id=plan.id,
            condition_kind=condition,
            benchmark_case_id=case_id,
            role=normalized_role,
            repetition_index=repetition_index,
        )
        return cls(
            id=identity,
            experiment_plan_id=plan.id,
            condition_kind=condition,
            benchmark_case_id=case_id,
            role=normalized_role,
            repetition_index=repetition_index,
        )


def expected_experiment_invocation_keys(
    plan: RealModelExperimentPlan,
    *,
    condition_kind: AblationConditionKind | str,
) -> list[ExperimentCaseInvocationKey]:
    """Return the exact case-by-role Phase 10D v1 invocation matrix."""

    if not isinstance(plan, RealModelExperimentPlan):
        raise TypeError("expected invocation keys require RealModelExperimentPlan")
    condition = AblationConditionKind(condition_kind)
    if condition not in _MODEL_CONDITIONS:
        return []
    return [
        ExperimentCaseInvocationKey.create(
            plan,
            condition_kind=condition,
            benchmark_case_id=case_id,
            role=role,
            repetition_index=0,
        )
        for case_id in plan.case_ids
        for role in PHASE10D_PROVIDER_ROLE_ORDER
    ]


def structured_prompt_request_sha256(request: StructuredPromptRequest) -> str:
    """Hash the exact bounded prompt fields supplied to a provider."""

    if not isinstance(request, StructuredPromptRequest):
        raise TypeError("prompt hash requires StructuredPromptRequest")
    snapshot = StructuredPromptRequest.model_validate(
        request.model_dump(mode="json")
    )
    return structured_prompt_sha256(
        {
            "architecture": snapshot.architecture.value,
            "candidate_id": snapshot.candidate_id,
            "schema_name": snapshot.schema_name,
            "system_prompt": snapshot.system_prompt,
            "user_prompt": snapshot.user_prompt,
        }
    )


def provider_response_sha256(text: str) -> str:
    """Hash exact UTF-8 provider text without normalization or repair."""

    if not isinstance(text, str):
        raise TypeError("provider response hash requires text")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def real_model_invocation_failure_id(
    *,
    invocation_key_id: str,
    stage: RealModelInvocationFailureStage,
    failure_code: RealModelInvocationFailureCode,
    parser_failure_detail: StructuredParseFailureDetail | None = None,
) -> str:
    payload = {
        "failure_code": RealModelInvocationFailureCode(failure_code).value,
        "invocation_key_id": invocation_key_id,
        "stage": RealModelInvocationFailureStage(stage).value,
    }
    if parser_failure_detail is not None:
        payload["parser_failure_detail"] = StructuredParseFailureDetail(
            parser_failure_detail
        ).value
    return _canonical_hash("real-model-invocation-failure", payload)


class RealModelInvocationFailure(DomainModel):
    """Bounded invocation infrastructure failure without raw diagnostics."""

    id: Identifier
    invocation_key_id: Identifier
    stage: RealModelInvocationFailureStage
    failure_code: RealModelInvocationFailureCode
    parser_failure_detail: StructuredParseFailureDetail | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_experiment_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "RealModelInvocationFailure":
        expected = real_model_invocation_failure_id(
            invocation_key_id=self.invocation_key_id,
            stage=self.stage,
            failure_code=self.failure_code,
            parser_failure_detail=self.parser_failure_detail,
        )
        if (
            self.stage is not RealModelInvocationFailureStage.STRUCTURED_PARSE
            and self.parser_failure_detail is not None
        ):
            raise ValueError(
                "parser failure detail requires structured-parse stage"
            )
        if self.id != expected:
            raise ValueError("RealModelInvocationFailure ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        invocation_key: ExperimentCaseInvocationKey,
        *,
        stage: RealModelInvocationFailureStage | str,
        failure_code: RealModelInvocationFailureCode | str,
        parser_failure_detail: StructuredParseFailureDetail | str | None = None,
        metadata: Metadata | None = None,
    ) -> "RealModelInvocationFailure":
        if not isinstance(invocation_key, ExperimentCaseInvocationKey):
            raise TypeError("invocation failure requires invocation key")
        normalized_stage = RealModelInvocationFailureStage(stage)
        code = RealModelInvocationFailureCode(failure_code)
        detail = (
            StructuredParseFailureDetail(parser_failure_detail)
            if parser_failure_detail is not None
            else None
        )
        identity = real_model_invocation_failure_id(
            invocation_key_id=invocation_key.id,
            stage=normalized_stage,
            failure_code=code,
            parser_failure_detail=detail,
        )
        return cls(
            id=identity,
            invocation_key_id=invocation_key.id,
            stage=normalized_stage,
            failure_code=code,
            parser_failure_detail=detail,
            metadata=metadata or {},
        )


def model_invocation_record_id(
    *,
    invocation_key_id: str,
    provider_descriptor_id: str,
    execution_mode: ExperimentExecutionMode,
    structured_output_schema_name: str,
    prompt_sha256: str | None,
    provider_response_sha256_value: str | None,
    disposition: ModelInvocationDisposition,
    failure_id: str | None,
    blocked_by_role: ReasoningAgentType | None,
) -> str:
    return _canonical_hash(
        "model-invocation-record",
        {
            "disposition": ModelInvocationDisposition(disposition).value,
            "execution_mode": ExperimentExecutionMode(execution_mode).value,
            "failure_id": failure_id,
            "invocation_key_id": invocation_key_id,
            "blocked_by_role": (
                ReasoningAgentType(blocked_by_role).value
                if blocked_by_role is not None
                else None
            ),
            "prompt_sha256": prompt_sha256,
            "provider_descriptor_id": provider_descriptor_id,
            "provider_response_sha256": provider_response_sha256_value,
            "structured_output_schema_name": structured_output_schema_name,
        },
    )


class ModelInvocationRecord(DomainModel):
    """Hash-only model invocation provenance; never semantic truth."""

    id: Identifier
    invocation_key: ExperimentCaseInvocationKey
    provider_descriptor_id: Identifier
    execution_mode: ExperimentExecutionMode
    structured_output_schema_name: Identifier
    prompt_sha256: Identifier | None = None
    provider_response_sha256: Identifier | None = None
    disposition: ModelInvocationDisposition
    failure: RealModelInvocationFailure | None = None
    blocked_by_role: ReasoningAgentType | None = None
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("prompt_sha256", "provider_response_sha256")
    @classmethod
    def validate_optional_hash(cls, value: str | None) -> str | None:
        return _validate_sha256(value, "invocation hash") if value is not None else None

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_experiment_metadata(value)

    @model_validator(mode="after")
    def validate_shape_and_identity(self) -> "ModelInvocationRecord":
        if self.disposition is ModelInvocationDisposition.COMPLETED:
            if (
                self.prompt_sha256 is None
                or self.provider_response_sha256 is None
                or self.failure is not None
                or self.blocked_by_role is not None
            ):
                raise ValueError(
                    "completed invocation requires both hashes and no failure/blocker"
                )
        elif self.disposition is ModelInvocationDisposition.FAILED:
            if self.failure is None or self.blocked_by_role is not None:
                raise ValueError(
                    "failed invocation requires bounded failure and no blocker"
                )
            if (
                self.provider_response_sha256 is not None
                and self.prompt_sha256 is None
            ):
                raise ValueError("invocation response hash requires prompt hash")
            stage = self.failure.stage
            if (
                stage is RealModelInvocationFailureStage.PROMPT_CONSTRUCTION
                and self.provider_response_sha256 is not None
            ):
                raise ValueError(
                    "prompt-construction failure cannot contain response hash"
                )
            if stage in {
                RealModelInvocationFailureStage.PROVIDER_CONNECTION,
                RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
                RealModelInvocationFailureStage.PROVIDER_RESPONSE,
                RealModelInvocationFailureStage.STRUCTURED_PARSE,
                RealModelInvocationFailureStage.WORKFLOW_ASSEMBLY,
            } and self.prompt_sha256 is None:
                raise ValueError("post-prompt failure requires prompt hash")
            if stage in {
                RealModelInvocationFailureStage.PROVIDER_CONNECTION,
                RealModelInvocationFailureStage.PROVIDER_TRANSPORT,
            } and self.provider_response_sha256 is not None:
                raise ValueError(
                    "pre-response provider failure cannot contain response hash"
                )
            if stage in {
                RealModelInvocationFailureStage.STRUCTURED_PARSE,
                RealModelInvocationFailureStage.WORKFLOW_ASSEMBLY,
            } and self.provider_response_sha256 is None:
                raise ValueError("post-response failure requires response hash")
        else:
            if (
                self.prompt_sha256 is not None
                or self.provider_response_sha256 is not None
                or self.failure is not None
                or self.blocked_by_role is None
            ):
                raise ValueError(
                    "not-attempted invocation requires only a blocking role"
                )
            if self.blocked_by_role not in _PHASE10D_PROVIDER_ROLES:
                raise ValueError("unsupported Phase 10D blocking role")
            role_index = PHASE10D_PROVIDER_ROLE_ORDER.index(
                self.invocation_key.role
            )
            blocker_index = PHASE10D_PROVIDER_ROLE_ORDER.index(
                self.blocked_by_role
            )
            if blocker_index >= role_index:
                raise ValueError(
                    "not-attempted invocation must reference an earlier role"
                )
        if self.failure is not None and (
            self.failure.invocation_key_id != self.invocation_key.id
        ):
            raise ValueError("invocation failure binding mismatch")
        expected = model_invocation_record_id(
            invocation_key_id=self.invocation_key.id,
            provider_descriptor_id=self.provider_descriptor_id,
            execution_mode=self.execution_mode,
            structured_output_schema_name=self.structured_output_schema_name,
            prompt_sha256=self.prompt_sha256,
            provider_response_sha256_value=self.provider_response_sha256,
            disposition=self.disposition,
            failure_id=self.failure.id if self.failure is not None else None,
            blocked_by_role=self.blocked_by_role,
        )
        if self.id != expected:
            raise ValueError("ModelInvocationRecord ID is not deterministic")
        return self

    @staticmethod
    def _validate_plan_binding(
        plan: RealModelExperimentPlan,
        invocation_key: ExperimentCaseInvocationKey,
        provider_descriptor_id: str,
    ) -> None:
        if invocation_key.experiment_plan_id != plan.id:
            raise ValueError("invocation key belongs to another experiment plan")
        if invocation_key.benchmark_case_id not in plan.case_ids:
            raise ValueError("invocation case is outside frozen experiment plan")
        if provider_descriptor_id != plan.provider_descriptor.id:
            raise ValueError("invocation provider descriptor mismatch")

    @staticmethod
    def _validate_prompt_binding(
        plan: RealModelExperimentPlan,
        invocation_key: ExperimentCaseInvocationKey,
        prompt: StructuredPromptRequest,
    ) -> None:
        if prompt.schema_name != plan.provider_descriptor.schema_name:
            raise ValueError("invocation prompt schema and descriptor mismatch")
        try:
            prompt_role = ReasoningAgentType(prompt.role)
        except ValueError as error:
            raise ValueError("invocation prompt has unsupported reasoning role") from error
        if prompt_role is not invocation_key.role:
            raise ValueError("invocation prompt role and key role mismatch")

    @classmethod
    def completed(
        cls,
        plan: RealModelExperimentPlan,
        invocation_key: ExperimentCaseInvocationKey,
        *,
        prompt: StructuredPromptRequest,
        raw_provider_response: str,
        provider_descriptor_id: str | None = None,
        metadata: Metadata | None = None,
    ) -> "ModelInvocationRecord":
        """Record exact hashes without retaining prompt or response content."""

        key = ExperimentCaseInvocationKey.model_validate(
            invocation_key.model_dump(mode="json")
        )
        provider_id = provider_descriptor_id or plan.provider_descriptor.id
        cls._validate_plan_binding(plan, key, provider_id)
        cls._validate_prompt_binding(plan, key, prompt)
        prompt_hash = structured_prompt_request_sha256(prompt)
        response_hash = provider_response_sha256(raw_provider_response)
        values = {
            "invocation_key_id": key.id,
            "provider_descriptor_id": provider_id,
            "execution_mode": plan.execution_mode,
            "structured_output_schema_name": prompt.schema_name,
            "prompt_sha256": prompt_hash,
            "provider_response_sha256_value": response_hash,
            "disposition": ModelInvocationDisposition.COMPLETED,
            "failure_id": None,
            "blocked_by_role": None,
        }
        return cls(
            id=model_invocation_record_id(**values),
            invocation_key=key,
            provider_descriptor_id=provider_id,
            execution_mode=plan.execution_mode,
            structured_output_schema_name=prompt.schema_name,
            prompt_sha256=prompt_hash,
            provider_response_sha256=response_hash,
            disposition=ModelInvocationDisposition.COMPLETED,
            metadata=metadata or {},
        )

    @classmethod
    def failed(
        cls,
        plan: RealModelExperimentPlan,
        invocation_key: ExperimentCaseInvocationKey,
        *,
        failure: RealModelInvocationFailure,
        prompt: StructuredPromptRequest | None = None,
        raw_provider_response: str | None = None,
        provider_descriptor_id: str | None = None,
        metadata: Metadata | None = None,
    ) -> "ModelInvocationRecord":
        """Record a bounded failure and any hashes available before failure."""

        key = ExperimentCaseInvocationKey.model_validate(
            invocation_key.model_dump(mode="json")
        )
        failure_snapshot = RealModelInvocationFailure.model_validate(
            failure.model_dump(mode="json")
        )
        provider_id = provider_descriptor_id or plan.provider_descriptor.id
        cls._validate_plan_binding(plan, key, provider_id)
        if failure_snapshot.invocation_key_id != key.id:
            raise ValueError("invocation failure belongs to another key")
        if prompt is not None:
            cls._validate_prompt_binding(plan, key, prompt)
        prompt_hash = (
            structured_prompt_request_sha256(prompt) if prompt is not None else None
        )
        response_hash = (
            provider_response_sha256(raw_provider_response)
            if raw_provider_response is not None
            else None
        )
        values = {
            "invocation_key_id": key.id,
            "provider_descriptor_id": provider_id,
            "execution_mode": plan.execution_mode,
            "structured_output_schema_name": plan.provider_descriptor.schema_name,
            "prompt_sha256": prompt_hash,
            "provider_response_sha256_value": response_hash,
            "disposition": ModelInvocationDisposition.FAILED,
            "failure_id": failure_snapshot.id,
            "blocked_by_role": None,
        }
        return cls(
            id=model_invocation_record_id(**values),
            invocation_key=key,
            provider_descriptor_id=provider_id,
            execution_mode=plan.execution_mode,
            structured_output_schema_name=plan.provider_descriptor.schema_name,
            prompt_sha256=prompt_hash,
            provider_response_sha256=response_hash,
            disposition=ModelInvocationDisposition.FAILED,
            failure=failure_snapshot,
            metadata=metadata or {},
        )

    @classmethod
    def not_attempted(
        cls,
        plan: RealModelExperimentPlan,
        invocation_key: ExperimentCaseInvocationKey,
        *,
        blocked_by_role: ReasoningAgentType | str,
        provider_descriptor_id: str | None = None,
        metadata: Metadata | None = None,
    ) -> "ModelInvocationRecord":
        """Account for a role skipped after an earlier role failed."""

        key = ExperimentCaseInvocationKey.model_validate(
            invocation_key.model_dump(mode="json")
        )
        provider_id = provider_descriptor_id or plan.provider_descriptor.id
        cls._validate_plan_binding(plan, key, provider_id)
        blocker = ReasoningAgentType(blocked_by_role)
        values = {
            "invocation_key_id": key.id,
            "provider_descriptor_id": provider_id,
            "execution_mode": plan.execution_mode,
            "structured_output_schema_name": plan.provider_descriptor.schema_name,
            "prompt_sha256": None,
            "provider_response_sha256_value": None,
            "disposition": ModelInvocationDisposition.NOT_ATTEMPTED,
            "failure_id": None,
            "blocked_by_role": blocker,
        }
        return cls(
            id=model_invocation_record_id(**values),
            invocation_key=key,
            provider_descriptor_id=provider_id,
            execution_mode=plan.execution_mode,
            structured_output_schema_name=plan.provider_descriptor.schema_name,
            disposition=ModelInvocationDisposition.NOT_ATTEMPTED,
            blocked_by_role=blocker,
            metadata=metadata or {},
        )
