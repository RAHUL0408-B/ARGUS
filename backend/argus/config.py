"""Runtime configuration. Everything overridable by environment variables."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("ARGUS_DATA", ROOT / "data"))
ARTIFACT_DIR = DATA_DIR / "artifacts"
DB_PATH = DATA_DIR / "argus.db"
REFERENCE_DIR = Path(__file__).parent / "reference"
SAMPLES_DIR = ROOT / "samples"

TOOLS_CONTAINER = os.getenv("ARGUS_TOOLS_CONTAINER", "argus-tools")
LAB_NETWORK = os.getenv("ARGUS_LAB_NETWORK", "argus-lab_labnet")
ZAP_API = os.getenv("ARGUS_ZAP_API", "http://127.0.0.1:18090")
MSF_IMAGE = os.getenv("ARGUS_MSF_IMAGE", "metasploitframework/metasploit-framework")

# LLM is optional. Without a key the deterministic rule planner is used.
# If both are set, Gemini is tried first (see planner.llm_choose) purely because it was the one
# actually configured and tested for this build; either path falls back to the rule planner on any error.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
LLM_MODEL = os.getenv("ARGUS_LLM_MODEL", "claude-sonnet-5-5")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
# gemini-2.0-flash and gemini-2.5-flash are both retired for new callers as of this build; gemini-flash-latest
# (the current stable alias) was observed 503-overloaded on manual testing, so flash-lite is the safer default
# for a live demo: fast (~1-2s), reliable, and the planner's job (rank a short candidate list, write 2-3 sentences)
# does not need a larger model.
GEMINI_MODEL = os.getenv("ARGUS_GEMINI_MODEL", "gemini-flash-lite-latest")


def llm_provider_name() -> str:
    if GEMINI_API_KEY:
        return "gemini"
    if ANTHROPIC_API_KEY:
        return "claude"
    return "rules-only"

DEFAULT_TIMEOUT = int(os.getenv("ARGUS_TOOL_TIMEOUT", "300"))
MAX_AGENT_STEPS = int(os.getenv("ARGUS_MAX_STEPS", "24"))

DATA_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
