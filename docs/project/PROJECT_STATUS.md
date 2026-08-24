# ChipChain Project Status

## Stable Baseline

- Branch: `main`
- Stable tag: `phase-9b2b-stable`
- Stable commit: `7477fd8426fdfddf53076ba859696d2b0f4bc995`
- Baseline: Phase 9B2B Step 1～7 complete
- Canonical environment: Ubuntu; Windows is secondary portability regression

## Completed Capabilities

- ARM-only same-architecture cross-layer modeling and deterministic analysis
- Phase 9A-R interaction-centered static verification with Type III objective propagation still `not_implemented`
- Phase 9B1 passive QEMU RuntimeObservation and interaction-agnostic Runtime Evidence
- Phase 9B2A explicit dynamic trigger observation verification and read-only static/dynamic aggregation
- Phase 9B2B non-verifying Hypothesis, EvidenceRequest, ReasoningResult, knowledge retrieval, feedback, deterministic four-role mock workflow, and dynamic reasoning context binding

## Current Work

Phase 9B2C Step 1～2 are complete. Step 2 adds a fixed CODE → HARDWARE → VULNERABILITY →
ATTACK_CHAIN provider-backed workflow with one call per role over the same detached context. The
reduced provider DTO gives the LLM authority only over semantic proposal fields; typed Context and
role contracts deterministically supply component, attack-pattern, Evidence category/priority, and
dynamic-trigger bindings after provider-output validation. Real `qwen3.8-max` Chat Completions
strict-schema four-role acceptance passed.

## Remaining Work

- Later acceptance hardening and evaluation: planned, not implemented
- Type III objective hardware-to-firmware causal verification: not implemented
- Verified AttackChain projection and additional architectures: not implemented

## Boundaries and Non-Goals

Real or mock LLM output is reasoning only. It does not create Evidence, VerificationRecord,
AttackChain, causality, verification status, scoring changes, or vulnerability verdicts. Step 1 has
no retry loop, dynamic routing, voting, automatic evidence collection, API/GUI, or exploit generation.
Strict-schema or role failures do not retry, downgrade to JSON Object, switch providers, or fall back
to a mock provider. AttackChain remains hypothesis-only and prior-agent free text is not chained.
No secrets or machine-specific paths belong in this document.
