"""Settings, read once from the environment (a local .env file is loaded if present)."""
import os

from dotenv import load_dotenv

load_dotenv()


def _float(name: str, default: str) -> float:
    return float(os.getenv(name, default))


def _int(name: str, default: str) -> int:
    return int(os.getenv(name, default))


# Model provider: auto = Claude if ANTHROPIC_API_KEY is set, else Gemini if GEMINI_API_KEY is set, else none.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").strip().lower()
CLAUDE_MODEL = os.getenv("CHECKER_CLAUDE_MODEL", "claude-opus-5-5")
CLAUDE_EFFORT = os.getenv("CHECKER_CLAUDE_EFFORT", "low")          # per-message classification needs little thinking
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
GEMINI_RPM = _float("GEMINI_RPM", "10")                     # stay under the free tier's requests-per-minute limit

# Verdict policy (chosen on the golden set; see "Choosing the thresholds" in the README)
SAMPLES = _int("SAMPLES", "2")                              # self-consistency runs per check (3 in the PRD; golden v1: the third never changed a verdict)
SCAM_THRESHOLD = _float("SCAM_THRESHOLD", "0.70")           # mean confidence needed for a model-only "Likely scam"
GENUINE_THRESHOLD = _float("GENUINE_THRESHOLD", "0.80")     # mean confidence needed for "No scam signs found"

# Service limits
MAX_TEXT_CHARS = _int("MAX_TEXT_CHARS", "2000")
MAX_IMAGE_BYTES = _int("MAX_IMAGE_BYTES", "4000000")
RATE_LIMIT_PER_HOUR = _int("RATE_LIMIT_PER_HOUR", "30")
LOG_PATH = os.getenv("LOG_PATH", "data/logs/events.jsonl")
