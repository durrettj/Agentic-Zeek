# main entry point for running the MCP server and orchestrating agents
import asyncio
import logging
from mcp.server.fastmcp import FastMCP
from mcp import ClientSession, StdioServerParameters
from src.agent.security_agent_tools import mcp_server, MockLogDatabase, AnomalyReport, InvestigationResult
from src.data_processing.zeek_log_parser import ZeekLogParser
from src.data_processing.embedding_service import EmbeddingService
from src.ml_models.anomaly_detection_model import AnomalyDetector
from config.config import settings
import json
import time
import uuid

# Configure logging for the main agent
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Agent Implementations (Simplified for demonstration) ---

class LogIngestionAgent:
    def __init__(self, mcp_session: ClientSession, db: MockLogDatabase):
        self.mcp_session = mcp_session
        self.db = db
        self.parser = ZeekLogParser()
        logger.info("Log Ingestion Agent initialized.")

    async def ingest_and_process_log(self, raw_log_data: str, log_type: str):
        """Simulates ingesting, parsing, and storing a single log entry."""
        logger.info(f"LIA: Ingesting raw {log_type} log...")
        parsed_log = self.parser.parse_log_entry(raw_log_data, log_type)
        if parsed_log:
            # Simulate anonymization
            anonymized_log = self.parser.anonymize_log(parsed_log, log_type)
            # Store via MCP tool call (to central MCP server)
            try:
                result = await self.mcp_session.call_tool("store_processed_log_tool", arguments={"log_entry": anonymized_log})
                logger.info(f"LIA: Successfully stored processed log: {result}")
                return anonymized_log
            except Exception as e:
                logger.error(f"LIA: Failed to store processed log via MCP tool: {e}")
        return None

class AnomalyDetectionAgent:
    def __init__(self, mcp_session: ClientSession, db: MockLogDatabase):
        self.mcp_session = mcp_session
        self.db = db
        self.embedding_service = EmbeddingService(api_key=settings.GEMINI_API_KEY)
        self.anomaly_detector = AnomalyDetector() # Initialize with default model
        logger.info("Anomaly Detection Agent initialized.")

    async def run_detection_cycle(self):
        """Simulates a detection cycle on new logs."""
        logger.info("ADA: Starting anomaly detection cycle...")
        # In a real system, this would query the DB for new, unprocessed logs
        # For demo, let's use a mock log directly
        mock_log_entry = {
            "ts": time.time(),
            "uid": str(uuid.uuid4()),
            "id.orig_h": "192.168.1.100",
            "id.resp_h": "203.0.113.50",
            "proto": "tcp",
            "conn_state": "S0", # SYN sent, no response - could be a scan
            "duration": 0.0,
            "orig_bytes": 0,
            "resp_bytes": 0,
            "log_type": "conn",
            "summary": "Suspicious SYN scan attempt"
        }
        
        # Simulate a normal log for comparison
        normal_log_entry = {
            "ts": time.time(),
            "uid": str(uuid.uuid4()),
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "192.168.1.1",
            "proto": "udp",
            "conn_state": "S1",
            "duration": 10.5,
            "orig_bytes": 100,
            "resp_bytes": 200,
            "log_type": "dns",
            "summary": "Normal DNS query"
        }

        logs_to_process = [normal_log_entry, mock_log_entry] # Process both normal and anomalous

        for log_data in logs_to_process:
            log_text = json.dumps(log_data) # Convert dict to string for embedding
            try:
                embeddings = await self.embedding_service.generate_embeddings([log_text], task_type="CLUSTERING")
                if embeddings:
                    embedding_vector = embeddings
                    is_anomaly, score = self.anomaly_detector.detect(embedding_vector)

                    if is_anomaly:
                        logger.warning(f"ADA: Detected ANOMALY! Score: {score:.4f} for log UID: {log_data.get('uid')}")
                        anomaly_report = AnomalyReport(
                            anomaly_id=str(uuid.uuid4()),
                            timestamp=log_data['ts'],
                            log_type=log_data['log_type'],
                            source_ip=log_data.get('id.orig_h'),
                            destination_ip=log_data.get('id.resp_h'),
                            severity="High", # Example severity
                            summary=log_data.get('summary', 'Unspecified anomaly'),
                            raw_log_snippet=log_text,
                            extracted_features=log_data, # For simplicity, using raw log as features
                            anomaly_score=score,
                            embedding_vector=embedding_vector
                        )
                        # Report anomaly via MCP tool call
                        await self.mcp_session.call_tool("report_anomaly", arguments={"report": anomaly_report.model_dump()})
                    else:
                        logger.info(f"ADA: Log UID {log_data.get('uid')} is NORMAL. Score: {score:.4f}")
                else:
                    logger.error(f"ADA: Failed to generate embeddings for log UID {log_data.get('uid')}")
            except Exception as e:
                logger.error(f"ADA: Error during detection for log UID {log_data.get('uid')}: {e}")

class InvestigationAgent:
    def __init__(self, mcp_session: ClientSession, db: MockLogDatabase):
        self.mcp_session = mcp_session
        self.db = db
        logger.info("Investigation Agent initialized.")

    async def investigate_anomaly(self, anomaly_report: AnomalyReport):
        """
        Simulates investigation of a reported anomaly using LLM for explanation.
        This method would be triggered by the `report_anomaly` tool call.
        """
        logger.info(f"IVA: Investigating anomaly {anomaly_report.anomaly_id} - {anomaly_report.summary}")

        # 1. Get LLM explanation using MCP Prompt
        try:
            # Use the 'explain_security_anomaly' prompt defined in security_agent_tools.py
            prompt_ref = mcp_server.get_prompt_reference("explain_security_anomaly")
            
            # The prompt expects specific arguments
            prompt_args = {
                "anomaly_summary": anomaly_report.summary,
                "raw_log_snippet": anomaly_report.raw_log_snippet,
                "extracted_features": json.dumps(anomaly_report.extracted_features) # Pass as JSON string
            }

            # Call the prompt via session.create_message (sampling)
            # This simulates the LLM generating a response based on the prompt
            llm_response = await self.mcp_session.create_message(
                messages=.content.text)
                    )
                ],
                max_tokens=500,
                # Enable logprobs for confidence scoring (requires Vertex AI setup)
                # generation_config={"response_logprobs": True, "logprobs": 5}
            )

            explanation_text = ""
            if llm_response.content and isinstance(llm_response.content, types.TextContent):
                explanation_text = llm_response.content.text
                logger.info(f"IVA: LLM Explanation for {anomaly_report.anomaly_id}:\n{explanation_text}")
            else:
                logger.warning(f"IVA: LLM did not return text content for {anomaly_report.anomaly_id}.")

            # Simulate confidence score (if logprobs were enabled, parse them here)
            confidence_score = 0.85 # Placeholder

            # 2. Suggest remediation actions using another MCP Prompt
            available_tools = ["block_ip", "create_incident_ticket"] # Example tools
            prompt_ref_remediation = mcp_server.get_prompt_reference("suggest_remediation_actions")
            
            remediation_prompt_args = {
                "anomaly_explanation": explanation_text,
                "anomaly_id": anomaly_report.anomaly_id,
                "available_tools": available_tools
            }

            llm_remediation_response = await self.mcp_session.create_message(
                messages=.content.text)
                    )
                ],
                max_tokens=300,
                # Ensure LLM tries to output JSON for this prompt
                # generation_config={"response_mime_type": "application/json"}
            )

            suggested_actions_data = {}
            if llm_remediation_response.content and isinstance(llm_remediation_response.content, types.TextContent):
                try:
                    # Attempt to parse JSON from LLM response
                    suggested_actions_data = json.loads(llm_remediation_response.content.text)
                    logger.info(f"IVA: LLM Suggested Actions for {anomaly_report.anomaly_id}:\n{suggested_actions_data}")
                except json.JSONDecodeError:
                    logger.error(f"IVA: LLM remediation response was not valid JSON: {llm_remediation_response.content.text}")
            
            suggested_actions_list = [action['description'] for action in suggested_actions_data.get('suggested_actions',)]
            human_review_needed = suggested_actions_data.get('human_review_required', True) # Default to True for safety

            # 3. Update investigation result via MCP tool
            investigation_result = InvestigationResult(
                anomaly_id=anomaly_report.anomaly_id,
                status="Confirmed" if confidence_score > 0.7 else "Needs Review",
                explanation=explanation_text,
                suggested_actions=suggested_actions_list,
                human_review_required=human_review_needed,
                confidence_score=confidence_score,
                additional_context={"llm_raw_remediation_response": suggested_actions_data}
            )
            await self.mcp_session.call_tool("update_investigation_result", arguments={"result": investigation_result.model_dump()})

            if human_review_needed:
                await self.mcp_session.call_tool("escalate_for_human_review", arguments={
                    "anomaly_id": anomaly_report.anomaly_id,
                    "reason": suggested_actions_data.get('reason_for_human_review', 'LLM requested human review or low confidence.')
                })
            else:
                # Simulate executing automated actions if no human review needed
                for action_data in suggested_actions_data.get('suggested_actions',):
                    tool_name = action_data.get('tool_name')
                    if tool_name in available_tools: # Check if the tool is actually available
                        logger.info(f"IVA: Attempting to execute automated action: {tool_name} for {action_data.get('target')}")
                        # Example: Call block_ip tool
                        if tool_name == "block_ip":
                            await self.mcp_session.call_tool("block_ip", arguments={
                                "ip_address": action_data.get('target'),
                                "duration_minutes": 60, # Example duration
                                "reason": action_data.get('description')
                            })
                        elif tool_name == "create_incident_ticket":
                             await self.mcp_session.call_tool("create_incident_ticket", arguments={
                                "title": action_data.get('description'),
                                "description": f"Automated ticket for anomaly {anomaly_report.anomaly_id}. Explanation: {explanation_text}",
                                "severity": anomaly_report.severity
                            })
                    else:
                        logger.warning(f"IVA: Suggested tool '{tool_name}' not available or not configured for auto-execution.")

        except Exception as e:
            logger.error(f"IVA: Error during anomaly investigation for {anomaly_report.anomaly_id}: {e}", exc_info=True)


class RemediationAgent:
    def __init__(self, mcp_session: ClientSession, db: MockLogDatabase):
        self.mcp_session = mcp_session
        self.db = db
        logger.info("Remediation Agent initialized.")

    # The actual remediation actions are implemented as MCP tools in security_agent_tools.py
    # This agent primarily exposes those tools and would contain the logic to interact
    # with external systems (firewalls, EDR, ticketing) when its tools are called.
    # For this demo, the tool functions themselves contain the "simulation" of action.
    async def run(self):
        logger.info("Remediation Agent is running and awaiting tool calls.")
        # In a real scenario, this agent might listen for specific events or
        # poll the database for pending remediation actions.
        # For this demo, its functionality is exposed via the MCP tools directly.
        pass

# --- Main Orchestration ---

async def main():
    logger.info("Starting AI-Driven Zeek Log Analysis System...")

    # Initialize the central MCP server
    # The mcp_server instance is imported from security_agent_tools.py
    # and already has its tools, resources, and lifespan defined.
    
    # Run the MCP server in the background as an asyncio task
    # For stdio transport, it typically takes over the main loop.
    # For demonstration, we'll simulate a client session connecting to it.
    
    # In a real deployment, the MCP server would run as a separate process
    # and agents would connect to it via network transports (e.g., streamable-http).
    # For this single-script demo, we'll use a mock stdio client connection to the server.

    # Mock the stdio server parameters to connect to the in-memory FastMCP instance
    # This is a simplification for a single-script demo.
    # In production, you'd run mcp_server.run(transport="streamable-http") in one process
    # and clients would connect via streamablehttp_client("http://localhost:8000/mcp")
    
    # We'll use a direct client session for simplicity, bypassing actual stdio pipes
    # This requires the MockLogDatabase to be accessible directly by agents,
    # which is handled by passing `db` instance.
    
    # For a true multi-process setup, the agents would use ClientSession
    # to connect to the FastMCP server running in its own process.
    
    # Let's simulate the database and client session for the agents
    mock_db = MockLogDatabase()
    await mock_db.connect() # Manually connect mock DB for agents

    # Create a dummy client session for agents to call tools on the *same* mcp_server instance
    # This is NOT how you'd do it in a multi-process setup, but works for a single-script demo
    # where mcp_server is a global object.
    class DummyClientSession:
        def __init__(self, mcp_server_instance: FastMCP, db_instance: MockLogDatabase):
            self._mcp_server = mcp_server_instance
            self._db = db_instance # Direct access for demo simplicity

        async def call_tool(self, tool_name: str, arguments: Dict[str, Any]):
            logger.debug(f"DummyClientSession: Calling tool '{tool_name}' with args: {arguments}")
            # Simulate MCP context for tool invocation
            class MockRequestContext:
                class MockLifespanContext:
                    def __init__(self, db):
                        self.db = db
                def __init__(self, db):
                    self.lifespan_context = self.MockLifespanContext(db)
                async def info(self, msg): logger.info(f"MCP Context Info: {msg}")
                async def warning(self, msg): logger.warning(f"MCP Context Warning: {msg}")
                async def error(self, msg): logger.error(f"MCP Context Error: {msg}")
                async def report_progress(self, progress, total, message): logger.info(f"MCP Context Progress: {message} ({progress}/{total})")
                class MockSession:
                    async def create_message(self, messages, max_tokens, generation_config=None):
                        # This is where the actual LLM call would happen.
                        # For demo, simulate a response based on prompt title.
                        prompt_text = messages.content.text
                        if "Explain Security Anomaly" in prompt_text:
                            simulated_response = """
                            {
                                "Anomaly Description": "Unusual SYN scan attempt from internal IP to external host.",
                                "Potential Implications": "Reconnaissance, potential C2 beaconing, or misconfigured internal system.",
                                "Key Indicators": "conn_state: S0, duration: 0.0, orig_bytes: 0, resp_bytes: 0, proto: tcp",
                                "Confidence": 0.9
                            }
                            """
                        elif "Suggest Remediation Actions" in prompt_text:
                            simulated_response = """
                            {
                                "suggested_actions":,
                                "human_review_required": false,
                                "reason_for_human_review": ""
                            }
                            """
                        else:
                            simulated_response = "Simulated LLM response."
                        
                        return types.CreateMessageResult(
                            role="assistant",
                            content=types.TextContent(type="text", text=simulated_response),
                            model="simulated-gemini",
                            stopReason="endTurn"
                        )
                    async def send_resource_list_changed(self): logger.info("MCP Context: Resource list changed notification sent.")
                self.session = self.MockSession()

            mock_ctx = MockRequestContext(self._db)
            
            # Find and call the tool function directly from the mcp_server instance
            # This bypasses JSON-RPC serialization for simplicity in this demo
            tool_func = getattr(self._mcp_server, tool_name)
            if tool_func:
                # MCP tools are decorated functions, need to call their underlying method
                # This is a bit hacky for a direct call, but demonstrates the flow
                # In a real client, you'd use session.call_tool which handles this.
                # For this demo, we're simulating the session.call_tool behavior.
                
                # Directly call the decorated function with arguments and mock context
                # This assumes the tool function is defined as async def tool_name(args, ctx)
                # We need to extract the actual function from the decorator
                
                # A more robust way would be to use a real ClientSession connecting to a real server
                # For now, let's manually map to the functions defined in security_agent_tools.py
                
                if tool_name == "store_processed_log_tool":
                    return await mcp_server.store_processed_log_tool(arguments['log_entry'], mock_ctx)
                elif tool_name == "report_anomaly":
                    return await mcp_server.report_anomaly(AnomalyReport(**arguments['report']), mock_ctx)
                elif tool_name == "update_investigation_result":
                    return await mcp_server.update_investigation_result(InvestigationResult(**arguments['result']), mock_ctx)
                elif tool_name == "block_ip":
                    return await mcp_server.block_ip(arguments['ip_address'], arguments['duration_minutes'], arguments['reason'], mock_ctx)
                elif tool_name == "create_incident_ticket":
                    return await mcp_server.create_incident_ticket(arguments['title'], arguments['description'], arguments['severity'], mock_ctx)
                elif tool_name == "escalate_for_human_review":
                    return await mcp_server.escalate_for_human_review(arguments['anomaly_id'], arguments['reason'], mock_ctx)
                else:
                    raise ValueError(f"Simulated tool '{tool_name}' not implemented for direct call.")
            else:
                raise AttributeError(f"Tool '{tool_name}' not found on MCP server.")
        
        async def create_message(self, messages, max_tokens, generation_config=None):
            # This is the mock for LLM sampling calls
            # It will simulate the LLM response based on the prompt content
            return await MockRequestContext(self._db).session.create_message(messages, max_tokens, generation_config)

    # Initialize agents with the dummy client session and mock DB
    dummy_mcp_client_session = DummyClientSession(mcp_server, mock_db)
    lia = LogIngestionAgent(dummy_mcp_client_session, mock_db)
    ada = AnomalyDetectionAgent(dummy_mcp_client_session, mock_db)
    iva = InvestigationAgent(dummy_mcp_client_session, mock_db)
    rma = RemediationAgent(dummy_mcp_client_session, mock_db) # Remediation agent mostly exposes tools

    # --- Simulate Workflow ---

    # 1. Simulate Log Ingestion
    sample_conn_log = '{"ts":1678886400.123456,"uid":"CABCDEF123","id.orig_h":"192.168.1.5","id.orig_p":12345,"id.resp_h":"10.0.0.10","id.resp_p":80,"proto":"tcp","service":"http","duration":10.5,"orig_bytes":1000,"resp_bytes":2000,"conn_state":"SF"}'
    await lia.ingest_and_process_log(sample_conn_log, "conn")

    # 2. Simulate Anomaly Detection Cycle
    await ada.run_detection_cycle()

    # 3. Simulate Investigation of a detected anomaly
    # For this demo, we'll manually get the last reported anomaly from the mock DB
    # In a real system, the IVA would be triggered by an event from report_anomaly tool.
    if mock_db.anomalies:
        last_anomaly_id = list(mock_db.anomalies.keys())[-1]
        last_anomaly_report = mock_db.anomalies[last_anomaly_id]
        await iva.investigate_anomaly(last_anomaly_report)
    else:
        logger.info("No anomalies detected to investigate in this run.")

    logger.info("AI-Driven Zeek Log Analysis System simulation finished.")

if __name__ == "__main__":
    # This will run the main orchestration logic.
    # The FastMCP server itself is not run as a separate process in this single-script demo,
    # but its functions are called directly by the dummy client session.
    # To run the actual MCP server for external clients/Claude Desktop, you would use:
    # uv run python src/agent/security_agent_main.py (if main() runs mcp_server.run())
    # OR uv run mcp dev src/agent/security_agent_tools.py (to run the tools as a server)
    
    # For this demo, we just run the main async function which simulates the flow.
    asyncio.run(main())
