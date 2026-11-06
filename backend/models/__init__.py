"""ORM models. Importing this package registers every table on Base.metadata."""
from backend.models.change import CHANGE_STATUSES, Assessment, Change, Impact
from backend.models.config import (
    ACL_ACTIONS,
    CRITICALITIES,
    INTENT_ACTIONS,
    PROTOCOLS,
    AclRule,
    NetworkIntent,
    StaticRoute,
    Vlan,
)
from backend.models.device import DEVICE_TYPES, HOST_TYPES, L3_TYPES, Device
from backend.models.interface import INTERFACE_STATUSES, SWITCHPORT_MODES, Interface
from backend.models.lab import Lab
from backend.models.link import Link
from backend.models.network import Network
from backend.models.preview_scan import PreviewScan
from backend.models.saved_login import SavedLogin
from backend.models.user import User, UserGroup
from backend.models.analysis_record import AnalysisRecord
from backend.models.credential_profile import CredentialProfile, CredentialAssignment
from backend.models.device_config import ChangeExecution, DeviceConfig
from backend.models.ai import AiInsight, ChangeOutcome

__all__ = [
    "User", "UserGroup", "Network", "Device", "Interface", "Link", "Vlan", "StaticRoute", "AclRule", "NetworkIntent",
    "Change", "Assessment", "Impact", "Lab", "SavedLogin", "PreviewScan", "AnalysisRecord",
    "CredentialProfile", "CredentialAssignment", "DeviceConfig", "ChangeExecution", "AiInsight", "ChangeOutcome",
    "DEVICE_TYPES", "L3_TYPES", "HOST_TYPES", "INTERFACE_STATUSES", "SWITCHPORT_MODES",
    "ACL_ACTIONS", "PROTOCOLS", "INTENT_ACTIONS", "CRITICALITIES", "CHANGE_STATUSES",
]
