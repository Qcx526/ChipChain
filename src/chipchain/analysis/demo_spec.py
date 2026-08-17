"""Private Pydantic input format consumed only by DemoAnalyzer."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from chipchain.models import Architecture, Layer
from chipchain.models.common import DomainModel, Identifier, Metadata


class DemoFunctionSpec(DomainModel):
    """A function observation in a deterministic program fixture."""

    id: Identifier
    architecture: Architecture
    function_type: Literal["function", "driver_function"]
    symbol: Identifier
    layer: Layer
    address: Identifier


class DemoCallSpec(DomainModel):
    """A fixture call observation with an explicit call site."""

    id: Identifier
    architecture: Architecture
    caller_id: Identifier
    callee_id: Identifier
    callsite_address: Identifier
    instruction: Identifier


class DemoIoctlSpec(DomainModel):
    """A fixture firmware-to-driver ioctl interaction."""

    id: Identifier
    architecture: Architecture
    caller_function_id: Identifier
    interface_id: Identifier
    interface_name: Identifier
    driver_function_id: Identifier
    command: Identifier
    issue_address: Identifier
    issue_instruction: Identifier
    invoke_address: Identifier
    invoke_instruction: Identifier


class DemoMMIOAccessSpec(DomainModel):
    """A fixture MMIO access with an explicit target address."""

    id: Identifier
    architecture: Architecture
    function_id: Identifier
    register_id: Identifier
    register_name: Identifier
    address: Identifier
    access_type: Literal["mmio_read", "mmio_write"]
    instruction_address: Identifier
    instruction: Identifier


class DemoProgramSpec(DomainModel):
    """Auditable semantic input transformed by DemoAnalyzer into domain models."""

    id: Identifier
    artifact_id: Identifier
    sample_type: Literal["fixture"]
    source: Identifier
    architecture: Architecture
    functions: list[DemoFunctionSpec] = Field(min_length=1)
    calls: list[DemoCallSpec] = Field(default_factory=list)
    ioctls: list[DemoIoctlSpec] = Field(default_factory=list)
    mmio_accesses: list[DemoMMIOAccessSpec] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_fixture_integrity(self) -> "DemoProgramSpec":
        """Reject mixed architecture, duplicate IDs, and dangling observations."""

        all_observations = [*self.calls, *self.ioctls, *self.mmio_accesses]
        architecture_items = [*self.functions, *all_observations]
        if any(item.architecture is not self.architecture for item in architecture_items):
            raise ValueError("all demo objects must match the spec architecture")

        function_by_id = {item.id: item for item in self.functions}
        if len(function_by_id) != len(self.functions):
            raise ValueError("demo function IDs must be unique")

        observation_ids = [item.id for item in all_observations]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("demo observation IDs must be unique")

        for call in self.calls:
            if call.caller_id not in function_by_id or call.callee_id not in function_by_id:
                raise ValueError(f"call {call.id!r} references an unknown function")

        interface_definitions: dict[str, str] = {}
        for ioctl in self.ioctls:
            if ioctl.caller_function_id not in function_by_id:
                raise ValueError(f"ioctl {ioctl.id!r} has an unknown caller")
            driver = function_by_id.get(ioctl.driver_function_id)
            if driver is None:
                raise ValueError(f"ioctl {ioctl.id!r} has an unknown driver function")
            if driver.function_type != "driver_function" or driver.layer is not Layer.DRIVER:
                raise ValueError(
                    f"ioctl {ioctl.id!r} target must be a driver function"
                )
            previous_name = interface_definitions.setdefault(
                ioctl.interface_id, ioctl.interface_name
            )
            if previous_name != ioctl.interface_name:
                raise ValueError(
                    f"interface {ioctl.interface_id!r} has inconsistent definitions"
                )

        register_definitions: dict[str, tuple[str, str]] = {}
        for access in self.mmio_accesses:
            if access.function_id not in function_by_id:
                raise ValueError(f"MMIO access {access.id!r} has an unknown function")
            definition = (access.register_name, access.address)
            previous = register_definitions.setdefault(access.register_id, definition)
            if previous != definition:
                raise ValueError(
                    f"register {access.register_id!r} has inconsistent definitions"
                )

        return self
