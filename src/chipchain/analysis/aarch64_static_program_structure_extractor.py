"""Plan-independent partial AArch64 static program-structure extractor."""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from chipchain.analysis.errors import (
    AArch64StaticProgramStructureBackendError,
    AArch64StaticProgramStructureExtractorError,
    InvalidAnalysisInputError,
    UnsupportedArtifactError,
)
from chipchain.analysis.models import ProgramArtifact
from chipchain.analysis.static_program_structure_models import (
    StaticProgramCfgEdge,
    StaticProgramCfgSemantics,
    StaticProgramFunctionCfg,
    StaticProgramStructureInventory,
    StaticProgramStructureInventoryScope,
)
from chipchain.models.enums import Architecture


AARCH64_STATIC_PROGRAM_STRUCTURE_EXTRACTOR_PROFILE_CFGFAST_V1 = (
    "phase10d_aarch64_static_program_structure_extractor_cfgfast_v1"
)

_AARCH64_INSTRUCTION_SET = "aarch64"
_CFG_SEMANTICS = (
    StaticProgramCfgSemantics
    .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
)
_INVENTORY_SCOPE = (
    StaticProgramStructureInventoryScope
    .PARTIAL_OBJECTIVE_FUNCTION_LOCAL_CFG_INVENTORY
)


class AngrAArch64StaticProgramStructureExtractor:
    """Extract a partial objective function-local CFG inventory from one ELF."""

    def extract(
        self,
        artifact: ProgramArtifact,
    ) -> StaticProgramStructureInventory:
        """Return the frozen C2-A structure inventory for one AArch64 ELF."""

        artifact_snapshot, artifact_path = self._validate_input(artifact)
        initial_bytes = self._read_artifact_bytes(artifact_path)
        artifact_sha256 = hashlib.sha256(initial_bytes).hexdigest()
        angr = self._load_backend()
        try:
            project = angr.Project(str(artifact_path), auto_load_libs=False)
        except Exception as exc:
            raise InvalidAnalysisInputError(
                "angr could not load the declared AArch64 ELF artifact"
            ) from exc
        if (
            str(project.arch.name).upper() != "AARCH64"
            or int(project.arch.bits) != 64
        ):
            raise UnsupportedArtifactError("loaded ELF is not AArch64/64-bit")

        try:
            cfg = project.analyses.CFGFast(normalize=True)
            functions = self._extract_functions(
                artifact=artifact_snapshot,
                artifact_sha256=artifact_sha256,
                project=project,
                cfg=cfg,
            )
            final_bytes = self._read_artifact_bytes(artifact_path)
            if hashlib.sha256(final_bytes).hexdigest() != artifact_sha256:
                raise InvalidAnalysisInputError(
                    "artifact contents changed during static structure extraction"
                )
            return StaticProgramStructureInventory.create(
                architecture=Architecture.ARM,
                artifact_id=artifact_snapshot.id,
                artifact_sha256=artifact_sha256,
                analyzer_profile_id=(
                    AARCH64_STATIC_PROGRAM_STRUCTURE_EXTRACTOR_PROFILE_CFGFAST_V1
                ),
                instruction_set=_AARCH64_INSTRUCTION_SET,
                analysis_scope=_INVENTORY_SCOPE,
                functions=functions,
            )
        except (
            AArch64StaticProgramStructureExtractorError,
            InvalidAnalysisInputError,
            UnsupportedArtifactError,
        ):
            raise
        except (ValidationError, ValueError) as exc:
            raise InvalidAnalysisInputError(
                "extractor produced invalid AArch64 static program structure"
            ) from exc
        except Exception as exc:
            raise AArch64StaticProgramStructureBackendError(
                "angr AArch64 static program-structure analysis failed"
            ) from exc

    @staticmethod
    def _validate_input(
        artifact: ProgramArtifact,
    ) -> tuple[ProgramArtifact, Path]:
        try:
            snapshot = ProgramArtifact.model_validate(
                artifact.model_dump(mode="json")
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise InvalidAnalysisInputError(
                "static structure extraction requires a valid detached artifact"
            ) from exc
        if snapshot.architecture is not Architecture.ARM:
            raise UnsupportedArtifactError(
                "AArch64 static structure extraction supports ARM artifacts only"
            )
        if snapshot.artifact_type != "elf":
            raise UnsupportedArtifactError(
                "AArch64 static structure extraction supports ELF artifacts only"
            )
        if snapshot.path is None:
            raise InvalidAnalysisInputError(
                "AArch64 static structure extraction requires an artifact path"
            )
        path = Path(snapshot.path)
        if not path.is_file():
            raise InvalidAnalysisInputError(
                "AArch64 static structure artifact path is not a regular file"
            )
        return snapshot, path

    @staticmethod
    def _read_artifact_bytes(path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            raise InvalidAnalysisInputError(
                "could not read AArch64 static structure artifact bytes"
            ) from exc

    @staticmethod
    def _load_backend() -> Any:
        try:
            return importlib.import_module("angr")
        except (ImportError, OSError) as exc:
            raise AArch64StaticProgramStructureBackendError(
                "AArch64 structure extraction requires the optional 'angr' extra"
            ) from exc

    def _extract_functions(
        self,
        *,
        artifact: ProgramArtifact,
        artifact_sha256: str,
        project: Any,
        cfg: Any,
    ) -> list[StaticProgramFunctionCfg]:
        main_object = project.loader.main_object
        symbol_names = self._function_symbol_names(main_object)
        recovered = sorted(
            (
                function
                for function in cfg.kb.functions.values()
                if self._is_main_object_function(function, main_object)
            ),
            key=lambda item: int(item.addr),
        )
        functions: list[StaticProgramFunctionCfg] = []
        for function in recovered:
            function_address = int(function.addr)
            eligible_blocks = self._eligible_block_addresses(
                project=project,
                main_object=main_object,
                function=function,
            )
            if not eligible_blocks:
                continue
            endpoint_pairs = self._function_edge_pairs(
                function=function,
                eligible_blocks=eligible_blocks,
            )
            edges = [
                StaticProgramCfgEdge.create(
                    architecture=Architecture.ARM,
                    artifact_id=artifact.id,
                    artifact_sha256=artifact_sha256,
                    analyzer_profile_id=(
                        AARCH64_STATIC_PROGRAM_STRUCTURE_EXTRACTOR_PROFILE_CFGFAST_V1
                    ),
                    instruction_set=_AARCH64_INSTRUCTION_SET,
                    function_address=hex(function_address),
                    source_basic_block_address=hex(source),
                    target_basic_block_address=hex(target),
                    cfg_semantics=_CFG_SEMANTICS,
                )
                for source, target in endpoint_pairs
            ]
            names = symbol_names.get(function_address, frozenset())
            function_name = next(iter(names)) if len(names) == 1 else None
            functions.append(
                StaticProgramFunctionCfg.create(
                    architecture=Architecture.ARM,
                    artifact_id=artifact.id,
                    artifact_sha256=artifact_sha256,
                    analyzer_profile_id=(
                        AARCH64_STATIC_PROGRAM_STRUCTURE_EXTRACTOR_PROFILE_CFGFAST_V1
                    ),
                    instruction_set=_AARCH64_INSTRUCTION_SET,
                    function_address=hex(function_address),
                    function_name=function_name,
                    basic_block_addresses=[
                        hex(address) for address in eligible_blocks
                    ],
                    directed_edges=edges,
                    cfg_semantics=_CFG_SEMANTICS,
                )
            )
        return functions

    @staticmethod
    def _function_symbol_names(main_object: Any) -> dict[int, frozenset[str]]:
        names: dict[int, set[str]] = {}
        for symbol in main_object.symbols:
            if symbol.is_function and symbol.name:
                names.setdefault(int(symbol.rebased_addr), set()).add(
                    str(symbol.name)
                )
        return {
            address: frozenset(values)
            for address, values in names.items()
        }

    @staticmethod
    def _is_main_object_function(function: Any, main_object: Any) -> bool:
        return bool(
            main_object.contains_addr(int(function.addr))
            and not function.is_simprocedure
            and not function.is_plt
        )

    def _eligible_block_addresses(
        self,
        *,
        project: Any,
        main_object: Any,
        function: Any,
    ) -> tuple[int, ...]:
        eligible: list[int] = []
        for address in sorted(
            {int(value) for value in function.block_addrs_set}
        ):
            if not main_object.contains_addr(address):
                continue
            try:
                block = project.factory.block(address)
            except Exception as exc:
                raise AArch64StaticProgramStructureBackendError(
                    "angr could not materialize one recovered AArch64 block"
                ) from exc
            if int(block.addr) != address:
                raise AArch64StaticProgramStructureBackendError(
                    "angr materialized a block at an unexpected address"
                )
            if self._is_executable_block(main_object, block):
                eligible.append(address)
        return tuple(eligible)

    @staticmethod
    def _is_executable_block(main_object: Any, block: Any) -> bool:
        start = int(block.addr)
        size = int(block.size or 0)
        if size <= 0 or not main_object.contains_addr(start):
            return False
        end = start + size - 1
        if not main_object.contains_addr(end):
            return False
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
    def _function_edge_pairs(
        *,
        function: Any,
        eligible_blocks: tuple[int, ...],
    ) -> tuple[tuple[int, int], ...]:
        eligible = set(eligible_blocks)
        pairs: set[tuple[int, int]] = set()
        for source_node, target_node in function.graph.edges():
            source = getattr(source_node, "addr", None)
            target = getattr(target_node, "addr", None)
            if source is None or target is None:
                continue
            endpoints = (int(source), int(target))
            if endpoints[0] in eligible and endpoints[1] in eligible:
                pairs.add(endpoints)
        return tuple(sorted(pairs))
