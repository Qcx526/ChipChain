"""Small block-local VEX constant resolver for observable memory accesses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class MemoryAccessObservation:
    """One real load/store and its conservatively resolved effective address."""

    function_address: int
    block_address: int
    statement_index: int
    instruction_address: int
    instruction: str | None
    access_type: Literal["read", "write"]
    target_address: int | None
    resolver: str = "vex_block_constant_propagation"


def recover_function_memory_accesses(
    project: Any,
    function: Any,
) -> list[MemoryAccessObservation]:
    """Recover simple constant loads/stores from unoptimized VEX blocks.

    Register and temporary constants are propagated only within each basic
    block. Unsupported expressions become unknown instead of being guessed.
    """

    observations: list[MemoryAccessObservation] = []
    for block in sorted(function.blocks, key=lambda item: int(item.addr)):
        lifted = project.factory.block(
            int(block.addr),
            size=int(block.size),
            opt_level=0,
        )
        instructions = {
            int(item.address): f"{item.mnemonic.lower()} {item.op_str.strip()}".strip()
            for item in lifted.capstone.insns
        }
        registers: dict[int, int] = {}
        temporaries: dict[int, int] = {}
        instruction_address = int(block.addr)

        for statement_index, statement in enumerate(lifted.vex.statements):
            statement_kind = type(statement).__name__
            if statement_kind == "IMark":
                instruction_address = int(statement.addr)
                continue
            if statement_kind == "WrTmp":
                data = statement.data
                if type(data).__name__ == "Load":
                    target = _evaluate(data.addr, registers, temporaries)
                    observations.append(
                        MemoryAccessObservation(
                            function_address=int(function.addr),
                            block_address=int(block.addr),
                            statement_index=statement_index,
                            instruction_address=instruction_address,
                            instruction=instructions.get(instruction_address),
                            access_type="read",
                            target_address=target,
                        )
                    )
                    temporaries.pop(int(statement.tmp), None)
                else:
                    value = _evaluate(data, registers, temporaries)
                    _set_or_forget(temporaries, int(statement.tmp), value)
                continue
            if statement_kind == "Put":
                value = _evaluate(statement.data, registers, temporaries)
                _set_or_forget(registers, int(statement.offset), value)
                continue
            if statement_kind == "Store":
                target = _evaluate(statement.addr, registers, temporaries)
                observations.append(
                    MemoryAccessObservation(
                        function_address=int(function.addr),
                        block_address=int(block.addr),
                        statement_index=statement_index,
                        instruction_address=instruction_address,
                        instruction=instructions.get(instruction_address),
                        access_type="write",
                        target_address=target,
                    )
                )

    return sorted(
        observations,
        key=lambda item: (
            item.instruction_address,
            item.access_type,
            item.block_address,
            item.statement_index,
        ),
    )


def _set_or_forget(mapping: dict[int, int], key: int, value: int | None) -> None:
    if value is None:
        mapping.pop(key, None)
    else:
        mapping[key] = value


def _evaluate(
    expression: Any,
    registers: dict[int, int],
    temporaries: dict[int, int],
) -> int | None:
    """Evaluate the deliberately small integer VEX subset used by Phase 4B."""

    expression_kind = type(expression).__name__
    if expression_kind == "Const":
        return int(expression.con.value)
    if expression_kind == "RdTmp":
        return temporaries.get(int(expression.tmp))
    if expression_kind == "Get":
        return registers.get(int(expression.offset))
    if expression_kind != "Binop":
        return None

    values = [_evaluate(arg, registers, temporaries) for arg in expression.args]
    if any(value is None for value in values):
        return None
    left, right = (int(value) for value in values)
    operation = str(expression.op)
    bits = _operation_bits(operation)
    mask = (1 << bits) - 1 if bits is not None else None

    if operation.startswith("Iop_Add"):
        result = left + right
    elif operation.startswith("Iop_Sub"):
        result = left - right
    elif operation.startswith("Iop_And"):
        result = left & right
    elif operation.startswith("Iop_Or"):
        result = left | right
    elif operation.startswith("Iop_Xor"):
        result = left ^ right
    elif operation.startswith("Iop_Shl"):
        result = left << right
    elif operation.startswith("Iop_Shr"):
        result = left >> right
    else:
        return None
    return result & mask if mask is not None else result


def _operation_bits(operation: str) -> int | None:
    """Extract the result width from common scalar VEX operation names."""

    for bits in (8, 16, 32, 64):
        if operation.startswith(
            (
                f"Iop_Add{bits}",
                f"Iop_Sub{bits}",
                f"Iop_And{bits}",
                f"Iop_Or{bits}",
                f"Iop_Xor{bits}",
                f"Iop_Shl{bits}",
                f"Iop_Shr{bits}",
            )
        ):
            return bits
    return None
