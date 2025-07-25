#define the Pydantic models for structured data exchange between agents, particularly for anomaly reporting
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class AnomalyReport(BaseModel):
    """
    Represents a detected security anomaly.
    """
    anomaly_id: str = Field(..., description="Unique identifier for the anomaly.")
    timestamp: float = Field(..., description="Epoch timestamp when the anomaly was detected.")
    log_type: str = Field(..., description="Type of Zeek log (e.g., conn, dns, http) where anomaly was found.")
    source_ip: Optional[str] = Field(None, description="Source IP address involved in the anomaly.")
    destination_ip: Optional[str] = Field(None, description="Destination IP address involved in the anomaly.")
    severity: str = Field(..., description="Severity of the anomaly (e.g., 'Low', 'Medium', 'High', 'Critical').")
    summary: str = Field(..., description="A brief summary of the anomaly.")
    raw_log_snippet: str = Field(..., description="The raw log entry or snippet that triggered the anomaly.")
    extracted_features: Dict[str, Any] = Field(default_factory=dict, description="Key features extracted from the log entry.")
    anomaly_score: float = Field(..., description="Numerical score indicating the degree of anomaly.")
    embedding_vector: List[float] = Field(..., description="The embedding vector of the log entry.")
    potential_implications: Optional[str] = Field(None, description="Potential security implications of the anomaly.")

class InvestigationResult(BaseModel):
    """
    Represents the outcome of an anomaly investigation.
    """
    anomaly_id: str = Field(..., description="Unique identifier of the anomaly investigated.")
    status: str = Field(..., description="Status of the investigation (e.g., 'Investigating', 'Confirmed', 'False Positive', 'Remediated').")
    explanation: str = Field(..., description="Detailed explanation of the anomaly, its root cause, and context.")
    suggested_actions: List[str] = Field(default_factory=list, description="List of suggested remediation or follow-up actions.")
    human_review_required: bool = Field(..., description="True if human intervention is explicitly required.")
    confidence_score: Optional[float] = Field(None, description="LLM's confidence score for the explanation/actions (0.0-1.0).")
    additional_context: Dict[str, Any] = Field(default_factory=dict, description="Any additional relevant context gathered during investigation.")

class RemediationAction(BaseModel):
    """
    Represents a remediation action to be taken.
    """
    action_id: str = Field(..., description="Unique identifier for the remediation action.")
    anomaly_id: str = Field(..., description="ID of the anomaly this action addresses.")
    action_type: str = Field(..., description="Type of action (e.g., 'block_ip', 'quarantine_host', 'create_ticket').")
    target: str = Field(..., description="Target of the action (e.g., IP address, hostname, ticket system).")
    reason: str = Field(..., description="Reason for the action.")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Additional parameters for the action.")
    status: str = Field("Pending", description="Current status of the action (e.g., 'Pending', 'Executing', 'Completed', 'Failed').")
