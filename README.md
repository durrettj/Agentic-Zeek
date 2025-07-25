
Install uv: If you haven't already, install uv by following the instructions on their official website (e.g., curl -LsSf https://astral.sh/uv/install.sh | sh).

Run the setup script: Navigate to the root directory of your project (security-ai-agent/) in your terminal and run:

python scripts/environment_setup.py

This will initialize the uv project, create a .venv virtual environment, and install all necessary dependencies. It will also prompt you to set your API keys as environment variables. Make sure to set your GEMINI_API_KEY as an environment variable.

Activate the virtual environment:

On Linux/macOS: source.venv/bin/activate

On Windows (Command Prompt): .venv\Scripts\activate

On Windows (PowerShell): .venv\Scripts\Activate.ps1

Run the main agent system:

uv run python src/agent/security_agent_main.py

This will execute the main function in security_agent_main.py, which orchestrates the simulated log ingestion, anomaly detection, and investigation processes, demonstrating the inter-agent communication via the mocked MCP client.# zeek
