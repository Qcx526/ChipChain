"""Deterministic adapter that analyzes an auditable JSON program fixture."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from pydantic import ValidationError

from chipchain.analysis.analyzer import ProgramAnalyzer
from chipchain.analysis.demo_spec import DemoProgramSpec
from chipchain.analysis.errors import (
    InvalidAnalysisInputError,
    ProgramAnalysisError,
    UnsupportedArtifactError,
)
from chipchain.analysis.models import ProgramAnalysisResult, ProgramArtifact
from chipchain.models import (
    BehaviorEdge,
    BehaviorNode,
    Evidence,
    EvidenceType,
    Layer,
    NodeKind,
    RelationType,
)


class DemoAnalyzer(ProgramAnalyzer):
    """Transform a fixture program specification into observable behavior facts."""

    def analyze(self, artifact: ProgramArtifact) -> ProgramAnalysisResult:
        """Read, validate, and deterministically transform one fixture artifact."""

        if artifact.artifact_type != "fixture":
            raise UnsupportedArtifactError(
                f"DemoAnalyzer does not support artifact type {artifact.artifact_type!r}"
            )
        if artifact.path is None:
            raise InvalidAnalysisInputError("DemoAnalyzer requires an artifact path")

        spec = self._load_spec(Path(artifact.path))
        if spec.artifact_id != artifact.id:
            raise InvalidAnalysisInputError(
                "demo spec artifact_id does not match ProgramArtifact.id"
            )
        if spec.architecture is not artifact.architecture:
            raise InvalidAnalysisInputError(
                "demo spec architecture does not match ProgramArtifact architecture"
            )
        if (
            artifact.fixture_identifier is not None
            and artifact.fixture_identifier != spec.id
        ):
            raise InvalidAnalysisInputError(
                "fixture_identifier does not match the demo spec ID"
            )

        try:
            nodes = self._build_nodes(spec)
            edges, evidence = self._build_edges_and_evidence(spec, artifact)
            return ProgramAnalysisResult(
                artifact=artifact,
                architecture=artifact.architecture,
                nodes=sorted(nodes, key=lambda item: item.id),
                edges=sorted(edges, key=lambda item: item.id),
                evidence=sorted(evidence, key=lambda item: item.id),
                metadata={
                    "analyzer": "demo_analyzer",
                    "fixture": True,
                    "spec_id": spec.id,
                    "source": spec.source,
                },
            )
        except ValidationError as exc:
            raise ProgramAnalysisError(
                "DemoAnalyzer produced an invalid analysis result"
            ) from exc

    @staticmethod
    def _load_spec(path: Path) -> DemoProgramSpec:
        """Load fixture JSON while hiding parser and filesystem exception types."""

        try:
            raw_data = json.loads(path.read_text(encoding="utf-8"))
            return DemoProgramSpec.model_validate(raw_data)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise InvalidAnalysisInputError(
                f"failed to load a valid demo program spec from {path}"
            ) from exc

    @staticmethod
    def _build_nodes(spec: DemoProgramSpec) -> list[BehaviorNode]:
        """Discover function, interface, and register nodes from semantic input."""

        sensitive_reasons: dict[str, set[str]] = defaultdict(set)
        for access in spec.mmio_accesses:
            sensitive_reasons[access.function_id].add(access.access_type)

        nodes: list[BehaviorNode] = []
        for function in sorted(spec.functions, key=lambda item: item.id):
            reasons = sorted(sensitive_reasons.get(function.id, set()))
            nodes.append(
                BehaviorNode(
                    id=function.id,
                    kind=(
                        NodeKind.DRIVER_FUNCTION
                        if function.function_type == "driver_function"
                        else NodeKind.FUNCTION
                    ),
                    name=function.symbol,
                    architecture=spec.architecture,
                    layer=function.layer,
                    address=function.address,
                    metadata={
                        "fixture": True,
                        "function_address": function.address,
                        "symbol": function.symbol,
                        "sensitive": bool(reasons),
                        "sensitive_reasons": reasons,
                    },
                )
            )

        ioctl_by_interface: dict[str, list[str]] = defaultdict(list)
        interface_names: dict[str, str] = {}
        for ioctl in spec.ioctls:
            ioctl_by_interface[ioctl.interface_id].append(ioctl.command)
            interface_names[ioctl.interface_id] = ioctl.interface_name
        for interface_id in sorted(ioctl_by_interface):
            nodes.append(
                BehaviorNode(
                    id=interface_id,
                    kind=NodeKind.INTERFACE,
                    name=interface_names[interface_id],
                    architecture=spec.architecture,
                    layer=Layer.INTERFACE,
                    metadata={
                        "fixture": True,
                        "commands": sorted(set(ioctl_by_interface[interface_id])),
                        "interface_type": "ioctl",
                    },
                )
            )

        register_specs = {item.register_id: item for item in spec.mmio_accesses}
        for register_id in sorted(register_specs):
            register = register_specs[register_id]
            nodes.append(
                BehaviorNode(
                    id=register.register_id,
                    kind=NodeKind.REGISTER,
                    name=register.register_name,
                    architecture=spec.architecture,
                    layer=Layer.HARDWARE,
                    address=register.address,
                    metadata={
                        "fixture": True,
                        "fixture_address": True,
                        "register_address": register.address,
                    },
                )
            )
        return nodes

    @staticmethod
    def _build_edges_and_evidence(
        spec: DemoProgramSpec,
        artifact: ProgramArtifact,
    ) -> tuple[list[BehaviorEdge], list[Evidence]]:
        """Convert observations into typed relations and separate static evidence."""

        edges: list[BehaviorEdge] = []
        evidence: list[Evidence] = []

        for call in sorted(spec.calls, key=lambda item: item.id):
            evidence_id = f"{call.id}-evidence"
            edges.append(
                BehaviorEdge(
                    id=f"{call.id}-calls",
                    source_id=call.caller_id,
                    target_id=call.callee_id,
                    relation=RelationType.CALLS,
                    architecture=spec.architecture,
                    evidence_ids=[evidence_id],
                    metadata={"fixture": True, "observation": "call"},
                )
            )
            evidence.append(
                DemoAnalyzer._make_evidence(
                    evidence_id=evidence_id,
                    artifact=artifact,
                    address=call.callsite_address,
                    instruction=call.instruction,
                    metadata={
                        "observation": "call_xref",
                        "caller_id": call.caller_id,
                        "callee_id": call.callee_id,
                    },
                )
            )

        for ioctl in sorted(spec.ioctls, key=lambda item: item.id):
            issue_evidence_id = f"{ioctl.id}-issues-evidence"
            invoke_evidence_id = f"{ioctl.id}-invokes-evidence"
            edges.extend(
                [
                    BehaviorEdge(
                        id=f"{ioctl.id}-issues",
                        source_id=ioctl.caller_function_id,
                        target_id=ioctl.interface_id,
                        relation=RelationType.ISSUES,
                        architecture=spec.architecture,
                        evidence_ids=[issue_evidence_id],
                        metadata={
                            "fixture": True,
                            "command": ioctl.command,
                            "observation": "ioctl_issue",
                        },
                    ),
                    BehaviorEdge(
                        id=f"{ioctl.id}-invokes",
                        source_id=ioctl.interface_id,
                        target_id=ioctl.driver_function_id,
                        relation=RelationType.INVOKES,
                        architecture=spec.architecture,
                        evidence_ids=[invoke_evidence_id],
                        metadata={
                            "fixture": True,
                            "command": ioctl.command,
                            "observation": "ioctl_invoke",
                        },
                    ),
                ]
            )
            evidence.extend(
                [
                    DemoAnalyzer._make_evidence(
                        evidence_id=issue_evidence_id,
                        artifact=artifact,
                        address=ioctl.issue_address,
                        instruction=ioctl.issue_instruction,
                        metadata={
                            "observation": "ioctl_issue",
                            "command": ioctl.command,
                        },
                    ),
                    DemoAnalyzer._make_evidence(
                        evidence_id=invoke_evidence_id,
                        artifact=artifact,
                        address=ioctl.invoke_address,
                        instruction=ioctl.invoke_instruction,
                        metadata={
                            "observation": "ioctl_invoke",
                            "command": ioctl.command,
                        },
                    ),
                ]
            )

        for access in sorted(spec.mmio_accesses, key=lambda item: item.id):
            evidence_id = f"{access.id}-evidence"
            relation = (
                RelationType.MMIO_WRITE
                if access.access_type == "mmio_write"
                else RelationType.MMIO_READ
            )
            edges.append(
                BehaviorEdge(
                    id=f"{access.id}-{access.access_type}",
                    source_id=access.function_id,
                    target_id=access.register_id,
                    relation=relation,
                    architecture=spec.architecture,
                    evidence_ids=[evidence_id],
                    metadata={
                        "fixture": True,
                        "mmio_address": access.address,
                        "observation": access.access_type,
                    },
                )
            )
            evidence.append(
                DemoAnalyzer._make_evidence(
                    evidence_id=evidence_id,
                    artifact=artifact,
                    address=access.instruction_address,
                    instruction=access.instruction,
                    metadata={
                        "observation": access.access_type,
                        "mmio_address": access.address,
                        "register_id": access.register_id,
                    },
                )
            )
        return edges, evidence

    @staticmethod
    def _make_evidence(
        *,
        evidence_id: str,
        artifact: ProgramArtifact,
        address: str,
        instruction: str,
        metadata: dict[str, str],
    ) -> Evidence:
        """Create fixture static evidence with explicit non-real provenance."""

        return Evidence(
            id=evidence_id,
            type=EvidenceType.STATIC_ANALYSIS,
            source="demo_analyzer",
            artifact=artifact.id,
            address=address,
            instruction=instruction,
            confidence=1.0,
            verified=True,
            metadata={"fixture": True, **metadata},
        )
