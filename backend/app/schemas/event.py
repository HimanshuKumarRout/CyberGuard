"""
Unified Event Model (UEM) & Core Domain Schemas for CYBERGUARD
Adheres strictly to the canonical 7-stage processing contract.
"""
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from enum import Enum
import uuid
from pydantic import BaseModel, Field, ConfigDict


class RiskLevel(str, Enum):
    SAFE = "Safe"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class IncidentStatus(str, Enum):
    OPEN = "Open"
    IN_INVESTIGATION = "In Investigation"
    CONTAINED = "Contained"
    RESOLVED = "Resolved"


class Priority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class Indicator(BaseModel):
    indicator_type: str = Field(..., description="Type of detected threat indicator")
    indicator_value: str = Field(..., description="Observed value or snippet")
    severity: Severity = Field(..., description="Severity rating of this indicator")
    weight: float = Field(..., ge=0.0, le=1.0, description="Indicator weight in risk calculation")

    model_config = ConfigDict(use_enum_values=True)


class Explanation(BaseModel):
    summary: str = Field(..., description="High-level plain language assessment headline")
    evidence: List[str] = Field(default_factory=list, description="Concrete verifiable parameters")
    reasoning: str = Field(..., description="Contextual narrative explaining risk synthesis")


class ResponseAction(BaseModel):
    action_type: str = Field(..., description="Standardized action identifier (e.g., block_url, revoke_session)")
    target: str = Field(..., description="Asset or subject of the action")
    priority: Priority = Field(default=Priority.P2, description="Execution priority")
    simulation_status: str = Field(default="Simulated", description="Execution mode: Simulated or Executed")
    details: Optional[str] = Field(default=None, description="Additional context or command metadata")

    model_config = ConfigDict(use_enum_values=True)


class UnifiedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:16]}", description="Unique event identifier")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO 8601 event timestamp")
    source: str = Field(default="api_gateway", description="Originating ingestion source")
    user_id: Optional[str] = Field(default=None, description="Associated user ID")
    device_id: Optional[str] = Field(default=None, description="Associated device fingerprint")
    input_type: str = Field(..., description="Input modality: email, url, image, audio, auth_log")
    detector: str = Field(..., description="Responsible detection module")
    threat_category: str = Field(..., description="Classified threat category")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detector model confidence (0.0 to 1.0)")
    risk_score: int = Field(..., ge=0, le=100, description="Normalized risk score (0 to 100)")
    risk_level: RiskLevel = Field(..., description="5-tier risk band")
    indicators: List[Indicator] = Field(default_factory=list, description="Extracted threat indicators")
    explanation: Explanation = Field(..., description="XAI structured rationale")
    recommended_actions: List[ResponseAction] = Field(default_factory=list, description="Containment recommendations")
    incident_status: Optional[str] = Field(default=None, description="Status if escalated to incident")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Detector-specific raw artifacts")

    model_config = ConfigDict(use_enum_values=True)


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"inc_{uuid.uuid4().hex[:12]}", description="Unique incident identifier")
    event_id: str = Field(..., description="Associated triggering event ID")
    title: str = Field(..., description="Descriptive incident headline")
    status: IncidentStatus = Field(default=IncidentStatus.OPEN, description="Current resolution state")
    priority: Priority = Field(default=Priority.P2, description="Triage priority")
    threat_category: str = Field(..., description="Classified attack modality")
    risk_score: int = Field(..., ge=0, le=100, description="Associated event risk score")
    risk_level: RiskLevel = Field(..., description="Severity tier")
    assigned_to: Optional[str] = Field(default="Unassigned", description="Assigned SOC analyst")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: Optional[str] = Field(default=None)

    model_config = ConfigDict(use_enum_values=True)


# Request schemas for Analysis Endpoints
class PhishingAnalysisRequest(BaseModel):
    text: str = Field(..., description="Email body, message, or subject line")
    url: Optional[str] = Field(default=None, description="Optional embedded link or suspicious URL")
    sender: Optional[str] = Field(default=None, description="Sender email address or header")


class ImpersonationAnalysisRequest(BaseModel):
    sender_name: str = Field(..., description="Claimed display name (e.g. CEO Jane Doe)")
    sender_address: str = Field(..., description="Actual transmitting address or handle")
    content: str = Field(..., description="Message text or communication payload")
    media_url: Optional[str] = Field(default=None, description="Optional profile image or audio URL")


class AnomalyAnalysisRequest(BaseModel):
    user_id: str = Field(..., description="Target corporate user account identifier")
    ip_address: str = Field(..., description="Client IP address initiating access")
    device_id: str = Field(..., description="Browser or device user-agent fingerprint")
    location: str = Field(default="Unknown", description="GeoIP location name or coordinates")
    failed_attempts: int = Field(default=0, ge=0, description="Consecutive failed logins prior to this event")
    session_duration: int = Field(default=0, ge=0, description="Active session duration in seconds")
    latitude: Optional[float] = Field(default=None, description="Geo latitude")
    longitude: Optional[float] = Field(default=None, description="Geo longitude")
