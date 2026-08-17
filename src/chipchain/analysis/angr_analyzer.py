"""Optional angr-backed ARM ELF program analysis adapter."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from chipchain.analysis.analyzer import ProgramAnalyzer
from chipchain.analysis.errors import (
    InvalidAnalysisInputError,
    ProgramAnalysisError,
    UnsupportedArtifactError,
)
from chipchain.analysis.models import ProgramAnalysisResult, ProgramArtifact
from chipchain.models import (
    Architecture,
    BehaviorEdge,
    BehaviorNode,
    Evidence,
    EvidenceType,
    Layer,
    NodeKind,
    RelationType,
)


class AngrAnalyzer(ProgramAnalyzer):
    """Recover ARM ELF functions and resolved calls with angr ``CFGFast``.

    angr is imported only when :meth:`analyze` runs, so importing ChipChain and
    using other analyzers does not require the optional native dependency.
    """

    def analyze(self, artifact: ProgramArtifact) -> ProgramAnalysisResult:
        """Analyze one ARM ELF without loading libraries or inferring vulnerabilities."""

        self._validate_artifact(artifact)
        angr = self._load_angr()
        artifact_path = Path(str(artifact.path))

        try:
            project = angr.Project(str(artifact_path), auto_load_libs=False)
        except Exception as exc:
            raise InvalidAnalysisInputError(
                f"angr could not load ELF artifact {artifact_path}"
            ) from exc

        if not project.arch.name.upper().startswith("ARM"):
            raise InvalidAnalysisInputError(
                "loaded ELF architecture does not match the ARM artifact declaration"
            )

        try:
            cfg = project.analyses.CFGFast(normalize=True)
            return self._build_result(
                artifact=artifact,
                angr=angr,
                project=project,
                cfg=cfg,
            )
        except ProgramAnalysisError:
            raise
        except ValidationError as exc:
            raise ProgramAnalysisError(
                "AngrAnalyzer produced an invalid analysis result"
            ) from exc
        except Exception as exc:
            raise ProgramAnalysisError("angr CFGFast analysis failed") from exc

    @staticmethod
    def _validate_artifact(artifact: ProgramArtifact) -> None:
        """Reject unsupported architectures, formats, and invalid paths early."""

        if artifact.architecture is not Architecture.ARM:
            raise UnsupportedArtifactError(
                "AngrAnalyzer Phase 4 supports only ARM artifacts"
            )
        if artifact.artifact_type != "elf":
            raise UnsupportedArtifactError(
                f"AngrAnalyzer does not support artifact type {artifact.artifact_type!r}"
            )
        if artifact.path is None:
            raise InvalidAnalysisInputError("AngrAnalyzer requires an artifact path")
        path = Path(artifact.path)
        if not path.is_file():
            raise InvalidAnalysisInputError(
                f"AngrAnalyzer artifact path is not a file: {path}"
            )

    @staticmethod
    def _load_angr() -> Any:
        """Load the optional backend with a stable installation error."""

        try:
            return importlib.import_module("angr")
        except (ImportError, OSError) as exc:
            raise ProgramAnalysisError(
                "AngrAnalyzer requires the optional dependency; "
                "install ChipChain with the 'angr' extra"
            ) from exc

    def _build_result(
        self,
        *,
        artifact: ProgramArtifact,
        angr: Any,
        project: Any,
        cfg: Any,
    ) -> ProgramAnalysisResult:
        """Normalize adapter-only angr objects into public domain models."""

        main_object = project.loader.main_object
        symbol_names = {
            int(symbol.rebased_addr): symbol.name
            for symbol in main_object.symbols
            if symbol.is_function and symbol.name
        }
        functions = {
            int(function.addr): function
            for function in cfg.kb.functions.values()
            if self._is_main_object_function(function, main_object)
        }

        nodes = [
            self._make_function_node(
                artifact=artifact,
                function=function,
                symbol_name=symbol_names.get(address),
            )
            for address, function in sorted(functions.items())
        ]
        edges, evidence, diagnostics = self._recover_calls(
            artifact=artifact,
            project=project,
            functions=functions,
        )

        return ProgramAnalysisResult(
            artifact=artifact,
            architecture=Architecture.ARM,
            nodes=sorted(nodes, key=lambda item: item.id),
            edges=sorted(edges, key=lambda item: item.id),
            evidence=sorted(evidence, key=lambda item: item.id),
            metadata={
                "analyzer": "angr_analyzer",
                "backend": "angr",
                "backend_version": str(angr.__version__),
                "cfg_algorithm": "CFGFast",
                "auto_load_libs": False,
                "main_object_only": True,
                "main_object_min_address": hex(int(main_object.min_addr)),
                "main_object_max_address": hex(int(main_object.max_addr)),
                "function_count": len(nodes),
                "resolved_call_count": len(edges),
                "unresolved_calls": diagnostics["unresolved_calls"],
                "excluded_external_call_count": diagnostics["external_calls"],
                "mmio_analysis": False,
                "fixture": bool(artifact.metadata.get("fixture", False)),
            },
        )

    @staticmethod
    def _is_main_object_function(function: Any, main_object: Any) -> bool:
        """Exclude SimProcedures, PLT entries, externs, and loader-owned stubs."""

        return bool(
            main_object.contains_addr(int(function.addr))
            and not function.is_simprocedure
            and not function.is_plt
        )

    def _make_function_node(
        self,
        *,
        artifact: ProgramArtifact,
        function: Any,
        symbol_name: str | None,
    ) -> BehaviorNode:
        """Create a deterministic function node with symbol provenance."""

        address = int(function.addr)
        name = symbol_name or self.synthetic_function_name(address)
        return BehaviorNode(
            id=self._function_id(artifact.id, address),
            kind=NodeKind.FUNCTION,
            name=name,
            architecture=Architecture.ARM,
            layer=Layer.FIRMWARE,
            address=hex(address),
            metadata={
                "analyzer": "angr_analyzer",
                "backend": "angr",
                "function_address": hex(address),
                "function_size": int(function.size or 0),
                "recovered": True,
                "symbol": symbol_name,
                "symbol_backed": symbol_name is not None,
                "fixture": bool(artifact.metadata.get("fixture", False)),
            },
        )

    def _recover_calls(
        self,
        *,
        artifact: ProgramArtifact,
        project: Any,
        functions: dict[int, Any],
    ) -> tuple[list[BehaviorEdge], list[Evidence], dict[str, int]]:
        """Recover resolved intra-object calls and count unresolved observations."""

        edges: list[BehaviorEdge] = []
        evidence: list[Evidence] = []
        unresolved_calls = 0
        external_calls = 0

        for caller_address, caller in sorted(functions.items()):
            for block_address in sorted(int(site) for site in caller.get_call_sites()):
                target = caller.get_call_target(block_address)
                instruction_address, instruction, call_type = self._callsite_details(
                    project=project,
                    function=caller,
                    block_address=block_address,
                    target_address=None if target is None else int(target),
                )
                if target is None:
                    unresolved_calls += 1
                    continue

                callee_address = self._match_function_address(int(target), functions)
                if callee_address is None:
                    if self._is_unresolvable_target(project, int(target)):
                        unresolved_calls += 1
                    else:
                        external_calls += 1
                    continue

                callsite = instruction_address or block_address
                edge_id = self._call_id(
                    artifact.id,
                    caller_address,
                    callee_address,
                    callsite,
                )
                evidence_id = f"{edge_id}:evidence"
                edges.append(
                    BehaviorEdge(
                        id=edge_id,
                        source_id=self._function_id(artifact.id, caller_address),
                        target_id=self._function_id(artifact.id, callee_address),
                        relation=RelationType.CALLS,
                        architecture=Architecture.ARM,
                        evidence_ids=[evidence_id],
                        metadata={
                            "analyzer": "angr_analyzer",
                            "backend": "angr",
                            "observation": "call_xref",
                            "call_type": call_type,
                            "callsite_address": hex(callsite),
                            "resolved": True,
                            "fixture": bool(artifact.metadata.get("fixture", False)),
                        },
                    )
                )
                evidence.append(
                    Evidence(
                        id=evidence_id,
                        type=EvidenceType.STATIC_ANALYSIS,
                        source="angr_analyzer",
                        artifact=artifact.id,
                        address=hex(callsite),
                        instruction=instruction,
                        confidence=1.0,
                        verified=True,
                        metadata={
                            "observation": "call_xref",
                            "backend": "angr",
                            "caller_address": hex(caller_address),
                            "callee_address": hex(callee_address),
                            "call_type": call_type,
                            "resolved": True,
                            "cfg_algorithm": "CFGFast",
                            "fixture": bool(artifact.metadata.get("fixture", False)),
                        },
                    )
                )

        return (
            edges,
            evidence,
            {"unresolved_calls": unresolved_calls, "external_calls": external_calls},
        )

    @staticmethod
    def _callsite_details(
        *,
        project: Any,
        function: Any,
        block_address: int,
        target_address: int | None,
    ) -> tuple[int | None, str | None, str]:
        """Recover the call instruction location/text without exposing Capstone."""

        instruction_address: int | None = None
        for source, destination, data in function.transition_graph.edges(data=True):
            if data.get("type") != "call" or int(source.addr) != block_address:
                continue
            destination_address = getattr(destination, "addr", None)
            if (
                target_address is None
                or destination_address is None
                or int(destination_address) == target_address
            ):
                raw_address = data.get("ins_addr")
                if raw_address is not None:
                    instruction_address = int(raw_address)
                    break

        try:
            instructions = project.factory.block(block_address).capstone.insns
        except Exception:
            instructions = []
        call_instruction = next(
            (
                item
                for item in reversed(instructions)
                if item.mnemonic.lower() in {"bl", "blx"}
            ),
            None,
        )
        if call_instruction is None:
            return instruction_address, None, "unknown"

        instruction_address = instruction_address or int(call_instruction.address)
        mnemonic = call_instruction.mnemonic.lower()
        operand = call_instruction.op_str.strip()
        instruction = f"{mnemonic} {operand}".strip()
        call_type = (
            "direct"
            if mnemonic == "bl" or operand.startswith("#")
            else "indirect"
        )
        return instruction_address, instruction, call_type

    @staticmethod
    def _is_unresolvable_target(project: Any, target_address: int) -> bool:
        """Distinguish angr's unresolved-call sink from resolved extern targets."""

        target = project.kb.functions.get(target_address)
        return bool(
            target is not None
            and target.is_simprocedure
            and target.name == "UnresolvableCallTarget"
        )

    @staticmethod
    def _match_function_address(
        target_address: int,
        functions: dict[int, Any],
    ) -> int | None:
        """Match exact and ARM/Thumb-normalized target addresses."""

        if target_address in functions:
            return target_address
        normalized = target_address & ~1
        return normalized if normalized in functions else None

    @staticmethod
    def synthetic_function_name(address: int) -> str:
        """Return the stable name used when no function symbol is available."""

        return f"sub_{address:08x}"

    @staticmethod
    def _function_id(artifact_id: str, address: int) -> str:
        return f"{artifact_id}:function:{address:08x}"

    @staticmethod
    def _call_id(
        artifact_id: str,
        caller_address: int,
        callee_address: int,
        callsite_address: int,
    ) -> str:
        return (
            f"{artifact_id}:call:{caller_address:08x}:"
            f"{callee_address:08x}:{callsite_address:08x}"
        )
