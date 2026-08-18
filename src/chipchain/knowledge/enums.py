"""Stable enums for the vulnerability knowledge graph contract."""

from __future__ import annotations

from enum import Enum


class KnowledgeNodeKind(str, Enum):
    """Entity kinds stored in the vulnerability knowledge graph."""

    VULNERABILITY = "vulnerability"
    CWE = "cwe"
    CAPEC = "capec"
    COMPONENT = "component"
    TRIGGER = "trigger"
    PRECONDITION = "precondition"
    BEHAVIOR = "behavior"
    INTERFACE = "interface"
    HARDWARE_RESOURCE = "hardware_resource"
    SECURITY_MECHANISM = "security_mechanism"
    IMPACT = "impact"
    ROOT_CAUSE = "root_cause"


class KnowledgeRelationType(str, Enum):
    """Semantic relations derived from a ``VulnerabilitySample``."""

    HAS_CWE = "has_cwe"
    HAS_CAPEC = "has_capec"
    AFFECTS_COMPONENT = "affects_component"
    HAS_TRIGGER = "has_trigger"
    REQUIRES_PRECONDITION = "requires_precondition"
    INVOLVES_BEHAVIOR = "involves_behavior"
    USES_INTERFACE = "uses_interface"
    TARGETS_RESOURCE = "targets_resource"
    INVOLVES_SECURITY_MECHANISM = "involves_security_mechanism"
    LEADS_TO_IMPACT = "leads_to_impact"
    HAS_ROOT_CAUSE = "has_root_cause"
