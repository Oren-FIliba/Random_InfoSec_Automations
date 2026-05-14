import os


BASE_DIR = os.environ.get("PIPELINE_BASE_DIR", ".")
DATA_DIR = os.environ.get("PIPELINE_DATA_DIR", f"{BASE_DIR}/pipeline_data")
ARTIFACTS_DIR = os.environ.get("PIPELINE_ARTIFACTS_DIR", f"{DATA_DIR}/artifacts")
REPORTS_DIR = os.environ.get("PIPELINE_REPORTS_DIR", f"{DATA_DIR}/reports")
TMP_DIR = os.environ.get("PIPELINE_TMP_DIR", f"{DATA_DIR}/tmp")
DB_PATH = os.environ.get("PIPELINE_DB_PATH", f"{DATA_DIR}/pipeline.db")

INGEST_API_HOST = os.environ.get("INGEST_API_HOST", "0.0.0.0")
INGEST_API_PORT = int(os.environ.get("INGEST_API_PORT", "8080"))
INGEST_API_TOKEN = os.environ.get("INGEST_API_TOKEN", "")

WORKER_POLL_INTERVAL = float(os.environ.get("WORKER_POLL_INTERVAL", "2.0"))
WORKER_TIMEOUT_SECONDS = int(os.environ.get("WORKER_TIMEOUT_SECONDS", "180"))

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "openai/gpt-5.3-codex")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
AI_MAX_FILES = int(os.environ.get("AI_MAX_FILES", "12"))
AI_MAX_CHARS_PER_FILE = int(os.environ.get("AI_MAX_CHARS_PER_FILE", "5000"))

AI_PROVIDER = os.environ.get("AI_PROVIDER", "opencode_local")
OPENCODE_CMD = os.environ.get("OPENCODE_CMD", "opencode")
OPENCODE_ARGS = os.environ.get("OPENCODE_ARGS", "run")
OPENCODE_MODE = os.environ.get("OPENCODE_MODE", "arg")  # stdin | arg | file
OPENCODE_TIMEOUT_SECONDS = int(os.environ.get("OPENCODE_TIMEOUT_SECONDS", "900"))

AI_BATCH_SIZE = int(os.environ.get("AI_BATCH_SIZE", "40"))
AI_MAX_RETRIES = int(os.environ.get("AI_MAX_RETRIES", "2"))
AI_TARGET_EXTENSIONS = tuple(
    ext.strip()
    for ext in os.environ.get("AI_TARGET_EXTENSIONS", ".js,.cjs,.mjs,.ts,.json,.sh").split(",")
    if ext.strip()
)
