"""Generic angr AArch64 binary CFG materialization for static case assembly.

This adapter is binary-first and pattern-agnostic. It materializes only
function-local CFG nodes and edges, then delegates all pairing and reachability
semantics to the frozen pure C1 assembler.
"""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from chipchain.analysis.models import ProgramArtifact
from chipchain.hardware_trigger.a_profile_static_case import (
    assemble_static_case_order_candidates,
)
from chipchain.hardware_trigger.a_profile_static_case_models import (
    AProfileStaticCaseAssemblyResult,
    AProfileStaticCfgEdge,
    AProfileStaticFunctionCfgSnapshot,
)
from chipchain.hardware_trigger.a_profile_static_semantic_angr import (
    AngrAProfileStaticSemanticExtractor,
)
from chipchain.hardware_trigger.a_profile_static_semantic_models import (
    AProfileStaticInstructionSetState,
    AProfileStaticSemanticExtractionPlan,
    AProfileStaticSemanticExtractionResult,
    AProfileStaticSemanticInstructionFact,
)
from chipchain.hardware_trigger.errors import (
    AProfileStaticCaseBackendError,
    AProfileStaticCaseMaterializationError,
    InvalidAProfileStaticCaseMaterializationInputError,
)
from chipchain.models.enums import Architecture


class AngrAProfileStaticCaseMaterializer:
    """Materialize relevant function CFGs from one immutable AArch64 ELF."""

    def materialize(
        self,
        artifact: ProgramArtifact,
        extraction_plan: AProfileStaticSemanticExtractionPlan,
    ) -> AProfileStaticCaseAssemblyResult:
        """Run semantic extraction, CFG normalization, and pure C1 assembly."""

        artifact_snapshot, plan_snapshot, artifact_path = self._validate_inputs(
            artifact,
            extraction_plan,
        )
        semantic_result = AngrAProfileStaticSemanticExtractor().extract(
            artifact_snapshot,
            plan_snapshot,
        )
        initial_bytes = self._read_artifact_bytes(artifact_path)
        artifact_sha256 = hashlib.sha256(initial_bytes).hexdigest()
        if artifact_sha256 != semantic_result.artifact_sha256:
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "CFG materialization artifact differs from semantic extraction"
            )

        angr = self._load_backend()
        try:
            project = angr.Project(str(artifact_path), auto_load_libs=False)
        except Exception as exc:
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "angr could not load the declared case-materialization ELF"
            ) from exc
        if (
            str(project.arch.name).upper() != "AARCH64"
            or int(project.arch.bits) != 64
        ):
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "loaded case-materialization ELF is not AArch64/64-bit"
            )

        try:
            cfg = project.analyses.CFGFast(normalize=True)
            snapshots = self._materialize_relevant_function_cfgs(
                semantic_result=semantic_result,
                project=project,
                cfg=cfg,
            )
            final_bytes = self._read_artifact_bytes(artifact_path)
            if hashlib.sha256(final_bytes).hexdigest() != artifact_sha256:
                raise InvalidAProfileStaticCaseMaterializationInputError(
                    "artifact contents changed during CFG materialization"
                )
            return assemble_static_case_order_candidates(
                semantic_result,
                snapshots,
            )
        except AProfileStaticCaseMaterializationError:
            raise
        except (ValidationError, ValueError) as exc:
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "normalized function CFG provenance is inconsistent"
            ) from exc
        except Exception as exc:
            raise AProfileStaticCaseBackendError(
                "angr function-CFG materialization failed"
            ) from exc

    @staticmethod
    def _validate_inputs(
        artifact: ProgramArtifact,
        extraction_plan: AProfileStaticSemanticExtractionPlan,
    ) -> tuple[
        ProgramArtifact,
        AProfileStaticSemanticExtractionPlan,
        Path,
    ]:
        try:
            artifact_snapshot = ProgramArtifact.model_validate(
                artifact.model_dump(mode="json")
            )
            plan_snapshot = AProfileStaticSemanticExtractionPlan.model_validate(
                extraction_plan.model_dump(mode="json")
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "case materialization requires valid detached inputs"
            ) from exc
        if artifact_snapshot.architecture is not Architecture.ARM:
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "case materialization supports ARM artifacts only"
            )
        if artifact_snapshot.artifact_type != "elf":
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "case materialization supports ELF artifacts only"
            )
        if artifact_snapshot.path is None:
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "case materialization requires an artifact path"
            )
        artifact_path = Path(artifact_snapshot.path)
        if not artifact_path.is_file():
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "case-materialization artifact is not a regular file"
            )
        if (
            plan_snapshot.architecture is not Architecture.ARM
            or plan_snapshot.architecture_profile != "a_profile"
            or plan_snapshot.target_instruction_set_state
            is not AProfileStaticInstructionSetState.AARCH64
        ):
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "case-materialization plan is outside A-profile AArch64 scope"
            )
        return artifact_snapshot, plan_snapshot, artifact_path

    @staticmethod
    def _read_artifact_bytes(path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "could not read case-materialization artifact bytes"
            ) from exc

    @staticmethod
    def _load_backend() -> Any:
        try:
            return importlib.import_module("angr")
        except (ImportError, OSError) as exc:
            raise AProfileStaticCaseBackendError(
                "case materialization requires the optional 'angr' extra"
            ) from exc

    def _materialize_relevant_function_cfgs(
        self,
        *,
        semantic_result: AProfileStaticSemanticExtractionResult,
        project: Any,
        cfg: Any,
    ) -> list[AProfileStaticFunctionCfgSnapshot]:
        relevant = self._relevant_function_facts(semantic_result)
        snapshots: list[AProfileStaticFunctionCfgSnapshot] = []
        for function_address in sorted(relevant, key=lambda item: int(item, 16)):
            facts = relevant[function_address]
            names = sorted(
                {
                    fact.function_name
                    for fact in facts
                    if fact.function_name is not None
                }
            )
            if len(names) > 1:
                raise InvalidAProfileStaticCaseMaterializationInputError(
                    "semantic facts disagree on recovered function name"
                )
            function = cfg.kb.functions.get(int(function_address, 16))
            if function is None:
                raise InvalidAProfileStaticCaseMaterializationInputError(
                    "exact relevant function is missing from recovered CFG"
                )
            if (
                not project.loader.main_object.contains_addr(int(function.addr))
                or function.is_simprocedure
                or function.is_plt
                or int(function.addr) != int(function_address, 16)
            ):
                raise InvalidAProfileStaticCaseMaterializationInputError(
                    "exact relevant function is not an eligible main-object function"
                )
            blocks, edges = self._normalize_function_graph(
                project=project,
                function=function,
            )
            for fact in facts:
                if fact.basic_block_address not in blocks:
                    raise InvalidAProfileStaticCaseMaterializationInputError(
                        "predicate-referenced fact block is missing from function CFG"
                    )
            snapshots.append(
                AProfileStaticFunctionCfgSnapshot.create(
                    extraction_result=semantic_result,
                    function_address=function_address,
                    function_name=names[0] if names else None,
                    basic_block_addresses=blocks,
                    directed_edges=edges,
                )
            )
        return snapshots

    @staticmethod
    def _relevant_function_facts(
        semantic_result: AProfileStaticSemanticExtractionResult,
    ) -> dict[str, list[AProfileStaticSemanticInstructionFact]]:
        fact_by_id = {item.id: item for item in semantic_result.instruction_facts}
        referenced_fact_ids = {
            item.static_instruction_fact_id
            for item in semantic_result.predicate_candidates
        }
        relevant: dict[str, list[AProfileStaticSemanticInstructionFact]] = {}
        for fact_id in sorted(referenced_fact_ids):
            fact = fact_by_id[fact_id]
            if fact.function_address is not None:
                relevant.setdefault(fact.function_address, []).append(fact)
        return relevant

    def _normalize_function_graph(
        self,
        *,
        project: Any,
        function: Any,
    ) -> tuple[list[str], list[AProfileStaticCfgEdge]]:
        main_object = project.loader.main_object
        block_addresses: set[int] = set()
        for address in sorted({int(item) for item in function.block_addrs_set}):
            if not main_object.contains_addr(address):
                continue
            try:
                block = project.factory.block(address)
            except Exception as exc:
                raise AProfileStaticCaseBackendError(
                    "angr could not materialize one relevant function block"
                ) from exc
            if self._is_executable_block(main_object, block):
                block_addresses.add(address)
        if not block_addresses:
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "relevant function has no executable main-object blocks"
            )

        edge_pairs: set[tuple[int, int]] = set()
        for source_node, target_node in function.graph.edges():
            source = getattr(source_node, "addr", None)
            target = getattr(target_node, "addr", None)
            if source is None or target is None:
                continue
            pair = (int(source), int(target))
            if pair[0] in block_addresses and pair[1] in block_addresses:
                edge_pairs.add(pair)
        blocks = [self._a64_address(item) for item in sorted(block_addresses)]
        edges = [
            AProfileStaticCfgEdge(
                source_basic_block_address=self._a64_address(source),
                target_basic_block_address=self._a64_address(target),
            )
            for source, target in sorted(edge_pairs)
        ]
        return blocks, edges

    @staticmethod
    def _is_executable_block(main_object: Any, block: Any) -> bool:
        start = int(block.addr)
        size = int(block.size or 0)
        if size <= 0:
            return False
        end = start + size - 1
        start_section = main_object.find_section_containing(start)
        end_section = main_object.find_section_containing(end)
        if start_section is not None or end_section is not None:
            return bool(
                start_section is not None
                and start_section is end_section
                and start_section.is_executable
            )
        start_segment = main_object.find_segment_containing(start)
        end_segment = main_object.find_segment_containing(end)
        return bool(
            start_segment is not None
            and start_segment is end_segment
            and start_segment.is_executable
        )

    @staticmethod
    def _a64_address(value: int) -> str:
        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise InvalidAProfileStaticCaseMaterializationInputError(
                "function CFG address is outside uint64"
            )
        return f"0x{value:016x}"
