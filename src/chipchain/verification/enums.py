"""Closed enums for deterministic interaction verification."""

from enum import Enum


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class ConditionStatus(str, Enum):
    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    UNKNOWN = "unknown"


class InteractionVerificationStatus(str, Enum):
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    REJECTED = "rejected"


class VerificationCapabilityStatus(str, Enum):
    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    NOT_IMPLEMENTED = "not_implemented"


class VerificationSubjectKind(str, Enum):
    INTERACTION_CONTRACT = "interaction_contract"
    INTERACTION_PARTICIPANT = "interaction_participant"
    BEHAVIOR_EDGE = "behavior_edge"
    ENTITY_LINK = "entity_link"
    KNOWLEDGE_EDGE = "knowledge_edge"
    ARCHITECTURE_RULE = "architecture_rule"
    CONDITION = "condition"
    DYNAMIC_TRIGGER_OBSERVATION = "dynamic_trigger_observation"


class InteractionReferenceRole(str, Enum):
    INITIATING_VULNERABILITY = "initiating_vulnerability"
    TARGET_VULNERABILITY = "target_vulnerability"
    TRIGGER_BEHAVIOR = "trigger_behavior"
    PROPAGATION_BEHAVIOR = "propagation_behavior"
    AFFECTED_EXECUTION = "affected_execution"
    FAULT_STATE = "fault_state"
    HARDWARE_RESOURCE = "hardware_resource"
    SECURITY_MECHANISM = "security_mechanism"


class InteractionSourceKind(str, Enum):
    BEHAVIOR_NODE = "behavior_node"
    BEHAVIOR_EDGE = "behavior_edge"
    KNOWLEDGE_NODE = "knowledge_node"
    KNOWLEDGE_EDGE = "knowledge_edge"
    ENTITY_LINK = "entity_link"
    EVIDENCE = "evidence"


class ConditionKind(str, Enum):
    TRIGGER = "trigger"
    PRECONDITION = "precondition"


class RequiredFactCategory(str, Enum):
    INITIATING_VULNERABILITY_SUPPORT = "initiating_vulnerability_support"
    TRIGGER_BEHAVIOR_SUPPORT = "trigger_behavior_support"
    CROSS_LAYER_TRANSITION_SUPPORT = "cross_layer_transition_support"
    TARGET_VULNERABILITY_SUPPORT = "target_vulnerability_support"
    HARDWARE_FAULT_STATE_SUPPORT = "hardware_fault_state_support"
    PROPAGATION_MECHANISM_SUPPORT = "propagation_mechanism_support"
    AFFECTED_EXECUTION_SUPPORT = "affected_execution_support"
    ARCHITECTURE_RULES = "architecture_rules"
    CONDITIONS = "conditions"


class LocationFindingStatus(str, Enum):
    LOCALIZED_CANDIDATE = "localized_candidate"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONTRADICTORY_CONTEXT = "contradictory_context"
    SEMANTIC_REFERENCE_ONLY = "semantic_reference_only"
