import os
import subprocess
import sys
import shutil

def run_command(command, message):
    """Executes a shell command and prints status messages."""
    print(f"\n--- {message} ---")
    try:
        subprocess.run(command, check=True, shell=True, capture_output=True, text=True)
        print(f"--- {message} completed successfully. ---")
    except subprocess.CalledProcessError as e:
        print(f"--- ERROR: {message} failed. ---")
        print(f"STDOUT:\n{e.stdout}")
        print(f"STDERR:\n{e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"--- ERROR: Command '{command.split()}' not found. Ensure UV is installed. ---")
        sys.exit(1)

def setup_uv_environment():
    """Initializes UV project, creates venv, and installs dependencies."""
    print("Starting UV environment setup...")

    # Check if uv is installed
    try:
        subprocess.run("uv --version", check=True, shell=True, capture_output=True, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("\nUV is not installed. Please install UV first:")
        print("  curl -LsSf https://astral.sh/uv/install.sh | sh")
        print("Or if you have pipx: pipx install uv")
        sys.exit(1)

    # Create project if not initialized (uv init)
    if not os.path.exists("pyproject.toml"):
        run_command("uv init", "Initializing UV project")
    else:
        print("\n--- UV project already initialized (pyproject.toml exists). Skipping init. ---")

    # Create virtual environment (uv venv)
    if not os.path.exists(".venv"):
        run_command("uv venv", "Creating virtual environment")
    else:
        print("\n--- Virtual environment (.venv) already exists. Skipping venv creation. ---")

    # Define core dependencies for the project
    core_dependencies = [
        "zat",
        "google-generativeai",
        "mcp[cli]",
        "scikit-learn",
        "pandas",
        "numpy",
        "pydantic" # Added for structured models
    ]

    # Add dependencies to pyproject.toml and install
    for dep in core_dependencies:
        run_command(f"uv add {dep}", f"Adding and installing {dep}")

    # Ensure requirements.txt exists by compiling pyproject.toml
    run_command("uv pip compile pyproject.toml -o requirements.txt", "Compiling dependencies to requirements.txt")

    print("\nUV environment setup complete.")

def manage_api_keys():
    """Guides user to set API keys as environment variables."""
    print("\n--- API Key Management ---")
    print("For security, API keys should be set as environment variables.")
    print("This script will guide you on how to set them locally.")
    print("For production deployments, consider dedicated secrets managers (e.g., Cloudflare Workers Secrets Store, AWS Secrets Manager, Azure Key Vault, Google Secret Manager).")

    api_keys_needed = {
        "OPENAI_API_KEY": "OpenAI API Key (if using OpenAI models)",
        "GEMINI_API_KEY": "Google Gemini API Key (for embeddings, decision-making)",
        "VOYAGE_API_KEY": "Voyage AI API Key (if using Voyage embeddings)",
        "ANTHROPIC_API_KEY": "Anthropic Claude API Key (if using Claude for anomaly explanation/tool use)"
    }

    print("\nPlease set the following environment variables:")
    for key, desc in api_keys_needed.items():
        print(f"- {key}: {desc}")
        if os.getenv(key):
            print(f"  (Currently set in environment: {'*' * 5})")
        else:
            print(f"  (Not currently set)")

    print("\nInstructions for setting environment variables (choose your OS/shell):")
    print("  Linux/macOS (Bash/Zsh):")
    print("    Edit ~/.bashrc or ~/.zshrc (or ~/.profile for system-wide):")
    print("    Example: echo 'export GEMINI_API_KEY=\"your_gemini_key_here\"' >> ~/.zshrc")
    print("    Then run: source ~/.zshrc")
    print("  Windows (Command Prompt):")
    print("    setx GEMINI_API_KEY \"your_gemini_key_here\"")
    print("  Windows (PowerShell):")
    print("    $env:GEMINI_API_KEY=\"your_gemini_key_here\"")
    print("\nRemember to restart your terminal or apply changes for variables to take effect.")
    print("For Cloudflare Workers, use `npx wrangler secret put <KEY_NAME>` to store secrets securely.")

if __name__ == "__main__":
    setup_uv_environment()
    manage_api_keys()
    print("\nSetup script finished. You can now activate your environment and run your agent:")
    print("  source.venv/bin/activate (Linux/macOS)")
    print(" .venv\\Scripts\\activate (Windows Cmd)")
    print(" .venv\\Scripts\\Activate.ps1 (Windows PowerShell)")
    print("Then: uv run python src/agent/security_agent_main.py")
