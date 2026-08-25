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

## Runtime Trigger Sequence Confirmation

Phase 9C Step 3A adds a separate concrete-execution relation:

```text
one StaticFirmwareTriggerMatch.id
        +
same artifact ID and exact ELF SHA-256
        +
one complete passive instruction trace
        |
        v
exact contiguous runtime occurrence of T
```

The Phase 9B1 observer and `chipchain_qemu_raw_trace` v2 remain unchanged. A dedicated
`chipchain-qemu-trigger-sequence-observer` emits isolated
`chipchain_qemu_trigger_sequence_trace` v1 JSONL. Translation records do not count as execution:
the plugin copies `qemu_plugin_insn_vaddr()`, `qemu_plugin_insn_size()` and
`qemu_plugin_insn_data()` output into plugin-owned metadata, and only its instruction execution
callback emits an event. The callback uses `QEMU_PLUGIN_CB_NO_REGS`; no register, CPSR, guest-memory
value, MMIO value or intervention API is used. Instrumentation callbacks may add execution overhead;
Step 3A makes no timing non-interference claim.

The strict trace requires one ARM system-emulation/single-vCPU header, contiguous instruction event
indexes from zero, and one clean end record with consistent counts. `instruction_bytes` is lowercase,
prefix-free hexadecimal with exactly two digits per byte. Candidate A32 matching requires size four,
then converts raw little-endian bytes to the same canonical logical word used by Steps 1/2:

```text
0100a0e3 -> 0xe3a00001
```

`RuntimeFirmwareTriggerMatcher` detached-revalidates both the normalized runtime trace and static
result. Runtime and static artifact ID plus firmware SHA-256 must match. For each static occurrence,
the matcher compares consecutive runtime events against every exact ordered `(PC, word)` pair. It
does not allow gaps, subsequences, reordered events, PC-only identity, word-only identity, CFG
reconstruction or cross-static-match splicing. Zero occurrences is valid and says only that this
concrete run did not execute that exact static occurrence.

`RuntimeFirmwareTriggerOccurrence.id` binds raw trace content SHA-256, firmware SHA-256, static match
ID, signature ID, exact runtime indexes, PCs and words. It excludes metadata, host path, timestamp,
QEMU/plugin paths and diagnostics. Public runtime results serialize no host paths or verdict fields.
The generic runner metadata records only observation-layer facts. It does not infer fixture,
synthetic, owned, benchmark, or real-vulnerability provenance from artifact/path/run/scenario names.
Owned fixture provenance remains explicit in the fixture files, Ground Truth, Signature metadata and
`ProgramArtifact` metadata.

The owned runtime fixture contains two static exact T functions, but `_start` calls only one before
semihosting exit. Static Step 2 therefore finds two occurrences while real Step 3A acceptance confirms
one. This demonstrates only exact runtime T execution on synthetic code; QEMU is not the vulnerable
RTL implementation.

## Preconditions and Explicit Non-Goals

Step 3A never evaluates declared P. In particular, it does not read r0-r15, CPSR/T-bit, privilege
mode, guest memory or memory values. Non-empty P is neither satisfied nor rejected by this result.
`ArmExecutionMode.A32` and `execution_scope=declared_arm_a32` describe the constrained runner and
fixture contract; they do not claim that Step 3A independently observed `CPSR.T == 0`.
The immutable distinctions are:

```text
static T != runtime T
runtime T != T + P
T + P != hardware failure reproduced in QEMU
```

Step 3B precondition-state confirmation is planned only if required by real samples. Step 3A creates
no Evidence, VerificationRecord, BehaviorEdge, AttackChain, vulnerability verdict, score, LLM output,
exploit or Phase 10 evaluation result.

## Triggerability Aggregation

Phase 9C Step 4 is a deterministic, non-LLM composition of three detached contracts:

```text
HardwareTriggerSignature: prior T + declared P -> known hardware failure
StaticFirmwareTriggerMatchResult: firmware structurally contains exact T
RuntimeFirmwareTriggerMatchResult: one concrete trace executed exact T
                              |
                              v
             TriggerabilityAggregationResult
```

The aggregator revalidates detached snapshots and then checks all cross-object bindings: architecture,
execution mode, signature/vulnerability identity, artifact ID/SHA-256, current static semantic hash,
the exact complete static-match ID set, signature/static ordered instruction words, and each runtime
occurrence's exact static-match PC/word sequence. Contradictory inputs raise typed exceptions; invalid
input and binding mismatch are never normal statuses.

The four closed statuses are:

- `triggerable`: at least one static exact T and corresponding runtime exact T exist, and the typed
  Signature declares no privilege/register/memory P;
- `insufficient_precondition_evidence`: static/runtime exact T exist, but one or more typed P remain
  objectively unconfirmed because Step 3B is not implemented;
- `not_observed_in_runtime`: static T exists, but this concrete trace/scenario has no occurrence;
- `no_static_trigger_match`: this artifact/signature result has no static exact T and no runtime
  occurrence.

There is deliberately no broad `not_triggerable` state. Missing precondition observation does not
make P false, and one trace not executing T does not prove firmware can never execute it. Declared P
is determined only from typed Signature fields, never metadata, proof wording, addresses or LLM text.

`runtime_trigger_match_result_sha256()` binds semantic Step 3A facts while excluding diagnostics and
occurrence metadata. `TriggerabilityAggregationResult.id` binds both static/runtime semantic hashes,
all contract/artifact/trace identities, exact match/occurrence IDs, declared-P presence and derived
status. Metadata, diagnostics, prose, proof descriptions, paths and timestamps do not affect identity.

For the owned synthetic empty-P fixture, the result is `TRIGGERABLE` under that declared synthetic
hardware-trigger contract. This means the supplied firmware objectively executed exact T for a
prevalidated contract with no additional declared P. It does not mean QEMU reproduced the hardware
failure, a real ARM vulnerability was confirmed, or an AttackChain was verified.

This Step 4 result is not yet the numerator for the project-level “关联漏洞命中率 >= 80%”. Phase 10
must first define a finalized candidate-chain identity, complete Type I/II chain semantics, a
chain-level feasibility oracle and denominator. Step 4 computes no hit rate; Phase 10 remains not
started.
