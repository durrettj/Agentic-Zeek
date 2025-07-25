#define the MCP Tools and Prompts that the agents will expose or use
from mcp.server.fastmcp import FastMCP, Context
from mcp.server.fastmcp.prompts import base
from src.agent.models import AnomalyReport, InvestigationResult, RemediationAction
from typing import List, Dict, Any, Optional
import asyncio
import logging

# Configure logging for this module
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize FastMCP server (this will be imported by security_agent_main.py)
# The name should be unique for the MCP server instance.
mcp_server = FastMCP("Zeek_Security_Agent_System")

# --- Database Mock (for demonstration purposes) ---
# In a real application, this would be a proper database connection
# managed via the FastMCP lifespan context.
class MockLogDatabase:
    def __init__(self):
        self.processed_logs = {} # Stores logs by uid
        self.anomalies = {} # Stores anomalies by anomaly_id
        self.investigations = {} # Stores investigation results
        self.remediation_actions = {} # Stores remediation actions

    async def connect(self):
        logger.info("MockLogDatabase connected.")
        return self

    async def disconnect(self):
        logger.info("MockLogDatabase disconnected.")

    async def store_processed_log(self, log_entry: Dict[str, Any]):
        uid = log_entry.get('uid') or log_entry.get('fuid') or str(log_entry.get('ts'))
        self.processed_logs[uid] = log_entry
        logger.info(f"Stored processed log: {uid}")
        return {"status": "success", "uid": uid}

    async def get_processed_log(self, log_type: str, uid: str) -> Optional]:
        log = self.processed_logs.get(uid)
        if log and log.get('log_type') == log_type: # Assuming log_type is stored in the log entry
            logger.info(f"Retrieved processed log: {uid}")
            return log
        logger.warning(f"Processed log {uid} of type {log_type} not found.")
        return None

    async def store_anomaly_report(self, report: AnomalyReport):
        self.anomalies[report.anomaly_id] = report
        logger.info(f"Stored anomaly report: {report.anomaly_id}")
        return {"status": "success", "anomaly_id": report.anomaly_id}

    async def get_anomaly_report(self, anomaly_id: str) -> Optional:
        report = self.anomalies.get(anomaly_id)
        if report:
            logger.info(f"Retrieved anomaly report: {anomaly_id}")
            return report
        logger.warning(f"Anomaly report {anomaly_id} not found.")
        return None

    async def store_investigation_result(self, result: InvestigationResult):
        self.investigations[result.anomaly_id] = result
        logger.info(f"Stored investigation result for anomaly: {result.anomaly_id}")
        return {"status": "success", "anomaly_id": result.anomaly_id}

    async def store_remediation_action(self, action: RemediationAction):
        self.remediation_actions[action.action_id] = action
        logger.info(f"Stored remediation action: {action.action_id}")
        return {"status": "success", "action_id": action.action_id}

# --- MCP Lifespan Context ---
# This manages shared resources like the database connection for all tools/resources.
class AppContext:
    """Application context with typed dependencies."""
    def __init__(self, db: MockLogDatabase):
        self.db = db

@mcp_server.lifespan()
async def app_lifespan(server: FastMCP):
    """Manage application lifecycle with type-safe context."""
    db = await MockLogDatabase().connect()
    try:
        yield AppContext(db=db)
    finally:
        await db.disconnect()

# --- MCP Resources ---

@mcp_server.resource("log_data://processed/{log_type}/{uid}")
async def get_processed_log_resource(log_type: str, uid: str, ctx: Context) -> Optional]:
    """
    Retrieve a processed Zeek log entry by type and UID.
    Exposed by the Log Ingestion Agent.
    """
    db = ctx.request_context.lifespan_context.db
    log_entry = await db.get_processed_log(log_type, uid)
    if log_entry:
        logger.info(f"Resource accessed: log_data://processed/{log_type}/{uid}")
        return log_entry
    return None

@mcp_server.resource("anomaly_report://{anomaly_id}")
async def get_anomaly_report_resource(anomaly_id: str, ctx: Context) -> Optional:
    """
    Retrieve a detected anomaly report by its ID.
    Exposed by the Anomaly Detection Agent.
    """
    db = ctx.request_context.lifespan_context.db
    report = await db.get_anomaly_report(anomaly_id)
    if report:
        logger.info(f"Resource accessed: anomaly_report://{anomaly_id}")
        return report
    return None

@mcp_server.resource("investigation_status://{anomaly_id}")
async def get_investigation_status_resource(anomaly_id: str, ctx: Context) -> Optional:
    """
    Retrieve the current status of an anomaly investigation.
    Exposed by the Investigation Agent.
    """
    db = ctx.request_context.lifespan_context.db
    result = db.investigations.get(anomaly_id) # Direct access for simplicity in mock
    if result:
        logger.info(f"Resource accessed: investigation_status://{anomaly_id}")
        return result
    return None

# --- MCP Tools ---

@mcp_server.tool()
async def store_processed_log_tool(log_entry: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Tool for the Log Ingestion Agent to store a processed Zeek log entry.
    """
    db = ctx.request_context.lifespan_context.db
    result = await db.store_processed_log(log_entry)
    await ctx.info(f"Log Ingestion Agent: Stored log with UID {result.get('uid')}")
    return result

@mcp_server.tool()
async def report_anomaly(report: AnomalyReport, ctx: Context) -> Dict[str, Any]:
    """
    Tool for the Anomaly Detection Agent to report a new anomaly.
    This will trigger the Investigation Agent.
    """
    db = ctx.request_context.lifespan_context.db
    result = await db.store_anomaly_report(report)
    await ctx.info(f"Anomaly Detection Agent: Reported anomaly {report.anomaly_id} - {report.summary}")
    # In a real system, this would trigger the Investigation Agent via a queue/event system
    # For this example, we'll just log it.
    return result

@mcp_server.tool()
async def update_investigation_result(result: InvestigationResult, ctx: Context) -> Dict[str, Any]:
    """
    Tool for the Investigation Agent to update the status and details of an investigation.
    """
    db = ctx.request_context.lifespan_context.db
    await db.store_investigation_result(result)
    await ctx.info(f"Investigation Agent: Updated investigation for anomaly {result.anomaly_id} - Status: {result.status}")
    return {"status": "success", "anomaly_id": result.anomaly_id}

@mcp_server.tool()
async def block_ip(ip_address: str, duration_minutes: int, reason: str, ctx: Context) -> Dict[str, Any]:
    """
    Tool for the Remediation Agent to block a suspicious IP address.
    (Simulated action)
    """
    action_id = f"block_{ip_address}_{asyncio.get_event_loop().time()}"
    action = RemediationAction(
        action_id=action_id,
        anomaly_id="N/A", # Should be linked to a real anomaly_id
        action_type="block_ip",
        target=ip_address,
        reason=reason,
        parameters={"duration_minutes": duration_minutes},
        status="Executing"
    )
    db = ctx.request_context.lifespan_context.db
    await db.store_remediation_action(action)
    await ctx.info(f"Remediation Agent: Initiated IP block for {ip_address} for {duration_minutes} mins. Reason: {reason}")
    # Simulate external system interaction
    await asyncio.sleep(1)
    action.status = "Completed"
    await db.store_remediation_action(action) # Update status
    return {"status": "success", "action_id": action_id, "message": f"IP {ip_address} blocked."}

@mcp_server.tool()
async def create_incident_ticket(title: str, description: str, severity: str, ctx: Context) -> Dict[str, Any]:
    """
    Tool for the Remediation Agent to create an incident ticket in a ticketing system.
    (Simulated action)
    """
    ticket_id = f"INC-{asyncio.get_event_loop().time()}"
    action = RemediationAction(
        action_id=ticket_id,
        anomaly_id="N/A", # Should be linked to a real anomaly_id
        action_type="create_ticket",
        target="TicketingSystem",
        reason=f"New incident: {title}",
        parameters={"title": title, "description": description, "severity": severity},
        status="Executing"
    )
    db = ctx.request_context.lifespan_context.db
    await db.store_remediation_action(action)
    await ctx.info(f"Remediation Agent: Created incident ticket '{title}' with ID {ticket_id}")
    await asyncio.sleep(0.5)
    action.status = "Completed"
    await db.store_remediation_action(action) # Update status
    return {"status": "success", "ticket_id": ticket_id, "message": f"Incident ticket created: {ticket_id}"}

@mcp_server.tool()
async def escalate_for_human_review(anomaly_id: str, reason: str, ctx: Context) -> Dict[str, Any]:
    """
    Tool for the Investigation Agent to escalate an anomaly for human review.
    """
    db = ctx.request_context.lifespan_context.db
    anomaly_report = await db.get_anomaly_report(anomaly_id)
    if anomaly_report:
        await ctx.warning(f"Human-in-the-Loop Agent: Escalated anomaly {anomaly_id} for human review. Reason: {reason}")
        # In a real system, this would send an alert to a human analyst dashboard/email/pager
        return {"status": "success", "anomaly_id": anomaly_id, "message": "Anomaly escalated for human review."}
    else:
        await ctx.error(f"Human-in-the-Loop Agent: Failed to escalate anomaly {anomaly_id}, not found.")
        return {"status": "error", "message": f"Anomaly {anomaly_id} not found."}

# --- MCP Prompts ---

@mcp_server.prompt(title="Explain Security Anomaly")
def explain_security_anomaly(anomaly_summary: str, raw_log_snippet: str, extracted_features: Dict[str, Any]) -> List[base.Message]:
    """
    Prompt for Gemini to provide a detailed explanation of a detected security anomaly.
    """
    prompt_text = f"""
    Analyze the following security anomaly and the associated Zeek log entry.
    Explain why this log might be anomalous, suggest potential security implications,
    and identify key fields that support this assessment.

    Anomaly Summary: {anomaly_summary}

    Raw Log Snippet:
    ```
    {raw_log_snippet}
    ```

    Extracted Features:
    ```json
    {extracted_features}
    ```

    Provide your explanation in a concise, structured format, highlighting:
    1.  **Anomaly Description:** What is unusual about this log?
    2.  **Potential Implications:** What security risks does this anomaly suggest (e.g., malware, data exfiltration, reconnaissance)?
    3.  **Key Indicators:** Which specific fields or values in the log/features support your assessment?
    4.  **Confidence:** On a scale of 0.0 to 1.0, how confident are you in this assessment?
    """
    return [base.UserMessage(prompt_text)]

@mcp_server.prompt(title="Suggest Remediation Actions")
def suggest_remediation_actions(anomaly_explanation: str, anomaly_id: str, available_tools: List[str]) -> List[base.Message]:
    """
    Prompt for Gemini to suggest specific remediation steps based on an anomaly explanation.
    """
    tools_list = ", ".join(available_tools) if available_tools else "No specific tools available."
    prompt_text = f"""
    Given the following security anomaly explanation and the anomaly ID,
    suggest immediate and follow-up remediation actions.
    Consider the available tools: {tools_list}.

    Anomaly ID: {anomaly_id}

    Anomaly Explanation:
    ```
    {anomaly_explanation}
    ```

    Provide your suggestions as a JSON object with the following structure:
    {{
        "suggested_actions": [
            {{
                "action_type": "string",
                "description": "string",
                "target": "string",
                "tool_name": "string" # Name of the MCP tool to call, if applicable (e.g., "block_ip")
            }}
        ],
        "human_review_required": boolean,
        "reason_for_human_review": "string" # Only if human_review_required is true
    }}
    """
    return [base.UserMessage(prompt_text)]
