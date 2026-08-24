# Hardware Trigger Signatures

## Scope

Phase 9C Step 1 models prior machine-level knowledge about a known hardware vulnerability or failure:

```text
exact TriggerSequence T
        +
declared Preconditions P
        |
        v
known primary hardware failure
```

The prior relation must come from owned, authorized, or auditable hardware-side work such as an RTL
versus golden-model differential mismatch or an assertion violation. `HardwareTriggerProof` retains
identifier-only provenance for that work but does not create a ChipChain `Evidence` object.

Future phases may separately establish:

```text
firmware can execute exact T
        +
declared P is satisfied
```

Only a later, explicitly designed aggregation step may combine those firmware-side facts with the
known hardware-trigger contract. Signature existence alone does not establish firmware
triggerability, vulnerability verification, causality, or an AttackChain.

## Exact ARM A32 Contract

Step 1 supports only `Architecture.ARM` with `ArmExecutionMode.A32` (`arm_a32`). The authoritative
trigger is a non-empty ordered list of address-independent 32-bit instruction words serialized as
`0x` plus exactly eight lowercase hexadecimal digits. Uppercase hexadecimal digits are normalized;
values wider or narrower than 32 bits, integer inputs, masks, wildcards, gaps, reordering, register
renaming, mnemonic similarity and semantic-equivalence matching are rejected or outside scope.

The signature contains no firmware ID, function ID or firmware instruction address. Thumb/T32,
AArch64 and all non-ARM architectures are unsupported in Step 1.

## Preconditions

`HardwareTriggerPreconditions` contains optional exact machine-state constraints:

- `privilege_mode`: one typed A32 architectural mode;
- `register_preconditions`: canonical `r0` through `r15` with exact uint32 values;
- `memory_preconditions`: exact ARM32 address, access size 1/2/4 bytes and exactly fitting value.

Register aliases `sp`, `lr` and `pc` are intentionally rejected. Register constraints are unique by
register; memory constraints are unique by `(address, access_size)`. Ranges, inequalities, masks,
symbolic expressions, address translation and MMIO-map linkage are not represented.

An empty precondition object means the available hardware-side knowledge declares no additional
machine-state requirement. It does not prove that hidden preconditions do not exist.

## Failure Effect and Proof

One signature records one primary `HardwareFailureEffect`:

- `register_mismatch` requires a canonical register plus distinct golden/architectural expected and
  vulnerable-hardware observed uint32 values;
- `assertion_violation` requires an assertion identifier and/or description and is not coerced into
  a register mismatch.

`HardwareTriggerProof` supports `golden_model_mismatch` and `assertion_violation`, with a non-empty,
duplicate-free list of provenance reference identifiers. It performs no network lookup or external
database validation and is not firmware execution evidence.

## Deterministic Identity

`HardwareTriggerSignature.create()` derives
`hardware-trigger-signature:<sha256>` from the semantic trigger contract:

- architecture and execution mode;
- hardware vulnerability reference;
- exact instruction sequence in original order;
- privilege, register and memory preconditions;
- expected hardware failure effect.

Register and memory constraint sets are normalized by their canonical keys. Instruction order is
never sorted. Metadata, proof description, proof kind and proof references remain serialized but do
not contribute to semantic identity. Consequently provenance rewording does not create a new trigger,
while an instruction, its order, a true precondition or failure semantics change does. Deserialization
recomputes the identity and rejects a retained ID attached to modified trigger semantics.

## Synthetic Fixture Boundary

`tests/fixtures/phase9c/arm_a32_hardware_trigger_signature.json` is owned synthetic contract data.
Its instruction words are harmless A32 arithmetic/move material, and its claimed mismatch is
synthetic. The fixture does not assert that real ARM hardware is vulnerable.

## Firmware Static Matching

Phase 9C Step 2 adds a separate static relation:

```text
authorized ARM ELF
        |
decoded executable A32 instructions
        |
function-local structurally reachable CFG path
        v
exact occurrence of TriggerSequence T
```

`FirmwareTriggerMatcher` first detached-revalidates the `ProgramArtifact` and
`HardwareTriggerSignature`. `AngrFirmwareTriggerMatcher` then hashes the actual ELF bytes, loads only
the main object with `auto_load_libs=False`, recovers `CFGFast(normalize=True)`, and builds a private
function/block/instruction view. Public callers never receive raw angr objects, and the existing
`ProgramAnalysisResult`/`AngrAnalyzer.analyze()` contracts remain unchanged.

Matching compares logical uint32 words extracted from decoded 4-byte A32 instructions using the
loaded architecture's instruction endianness. It never compares mnemonic or operand text and never
searches raw ELF bytes. Blocks must be executable and explicitly non-Thumb. Identical bytes in data,
rodata, symbols, padding or strings cannot enter the matching view.

Within a block, matched instructions are consecutive. Across blocks, the next instruction must be
the first instruction of a same-function sequence successor. The start block must be structurally
reachable from that recovered function's entry. This is not global boot-entry reachability and not
concrete input feasibility. Calls are not followed into callees; the bounded state walk consumes at
most the finite signature length and deduplicates loop states.

`StaticFirmwareTriggerMatch` records artifact ID/content SHA-256, signature/vulnerability references,
ARM/A32 identity, function address/name, exact instruction locations and ordered basic-block path.
Its deterministic ID excludes display-name wording, metadata, host path, timestamps, backend version
and diagnostics. A zero-match result is valid and means only that this matcher established no exact
static occurrence.

The owned fixture in `tests/fixtures/phase9c/arm_a32_trigger_match/` contains one executable exact
occurrence, one changed-word near miss and an identical raw byte copy in non-executable `.data`.

The following distinctions are immutable:

```text
static CFG match != actual runtime execution
static CFG match != concrete input/path feasibility
static CFG match != register/memory/privilege preconditions satisfied
static CFG match != hardware failure reproduced
static CFG match != vulnerability or triggerability verified
```

## Explicit Non-Goals

Step 2 implements no runtime instruction trace, dynamic sequence match, precondition evaluation,
triggerability aggregation, Evidence creation, VerificationRecord, AttackChain projection, score,
LLM matching, exploit generation or Phase 10 evaluation.
