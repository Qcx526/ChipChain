"""Stable string enums used by ChipChain JSON contracts."""

from __future__ import annotations

from enum import Enum


class Architecture(str, Enum):
    """Chip architectures understood by the shared domain layer."""

    ARM = "arm"
    RISC_V = "risc_v"
    POWERPC = "powerpc"
    SPARC = "sparc"
    LOONGARCH = "loongarch"


class Layer(str, Enum):
    """Physical or analytical layer represented by an entity."""

    FIRMWARE = "firmware"
    DRIVER = "driver"
    ARCHITECTURE = "architecture"
    HARDWARE = "hardware"
    INTERFACE = "interface"
    IMPACT = "impact"


class SampleType(str, Enum):
    """Provenance category for vulnerability samples."""

    REAL = "real"
    SYNTHETIC = "synthetic"
    DEMO = "demo"
    FIXTURE = "fixture"


class EvidenceType(str, Enum):
    """Origin of a piece of evidence."""

    KNOWLEDGE_GRAPH = "knowledge_graph"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    ARCHITECTURE_RULE = "architecture_rule"
    SOURCE_REFERENCE = "source_reference"
    LLM_SEMANTIC = "llm_semantic"


class ChainStatus(str, Enum):
    """Lifecycle state of an attack chain."""

    CANDIDATE = "candidate"
    PARTIALLY_VERIFIED = "partially_verified"
    VERIFIED = "verified"
    REJECTED = "rejected"


class EdgeVerificationStatus(str, Enum):
    """Result of verifying a single attack-chain edge."""

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    REJECTED = "rejected"


class BehaviorType(str, Enum):
    """Security-relevant program or hardware behavior."""

    CALL = "call"
    SYSCALL = "syscall"
    IOCTL = "ioctl"
    MMIO_READ = "mmio_read"
    MMIO_WRITE = "mmio_write"
    REGISTER_ACCESS = "register_access"
    DMA_READ = "dma_read"
    DMA_WRITE = "dma_write"
    INTERRUPT = "interrupt"
    PRIVILEGE_TRANSITION = "privilege_transition"
    DATA_FLOW = "data_flow"


class NodeKind(str, Enum):
    """Kinds of entities that may appear in graphs and attack chains."""

    VULNERABILITY = "vulnerability"
    FUNCTION = "function"
    DRIVER_FUNCTION = "driver_function"
    INTERFACE = "interface"
    REGISTER = "register"
    HARDWARE_RESOURCE = "hardware_resource"
    SECURITY_MECHANISM = "security_mechanism"
    WEAKNESS = "weakness"
    IMPACT = "impact"


class RelationType(str, Enum):
    """Typed relationships used in behavior graphs and linear chains."""

    CALLS = "calls"
    INVOKES = "invokes"
    ISSUES = "issues"
    DATA_FLOWS_TO = "data_flows_to"
    MMIO_READ = "mmio_read"
    MMIO_WRITE = "mmio_write"
    ACCESSES = "accesses"
    TRIGGERS = "triggers"
    EXPLOITS = "exploits"
    LEADS_TO = "leads_to"
