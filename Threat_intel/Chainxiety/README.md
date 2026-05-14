# Telegram Message to Webhook

Two Python scripts are included:

- `telegram_group_monitor.py`: preconfigured for the Supply Chain Monitor group.
- `telegram_channel_webhook.py`: generic version for any Telegram group or channel.

## What it does

- Authenticates with your Telegram account using Telethon.
- Watches a Telegram source for new messages.
- Sends each message to a webhook as JSON.
- Parses these fields from alert-style text when present:
  - `Package:`
  - `Ecosystem:`
  - `Summary:`
  - `Registry:`
- `telegram_group_monitor.py` also enriches npm alerts with:
  - `package_name` and `version` split from `Package:`
  - npm package metadata from `https://registry.npmjs.org/{package}/{version}`
  - weekly downloads from `https://api.npmjs.org/downloads/point/last-week/{package}`

## Install

```bash
python3 -m pip install telethon requests
```

## Telegram API credentials

Create Telegram API credentials at https://my.telegram.org:

- `api_id`
- `api_hash`

## Generic script usage (recommended)

### Option A: environment variables
```bash
export TG_API_ID="your_api_id"
export TG_API_HASH="your_api_hash"
export TG_PHONE="+1234567890"
export WEBHOOK_URL="https://your-webhook-endpoint"
export TG_SOURCE="https://t.me/+Pi4b85rUUKEzMjFk"
python3 telegram_channel_webhook.py
```

### Option B: CLI arguments

```bash
python3 telegram_channel_webhook.py \
  --api-id 31753339 \
  --api-hash "your_api_hash" \
  --phone "+972508104300" \
  --source "https://t.me/+Pi4b85rUUKEzMjFk" \
  --webhook-url "https://your-webhook-endpoint"
```

`--source` can be:

- Invite link (`https://t.me/+...`)
- Public username (`@channelname`)
- Public link (`https://t.me/channelname`)
- Numeric chat ID

## Test mode (send last N messages and exit)

```bash
python3 telegram_channel_webhook.py --send-last-n 2 --source "@channelname" --webhook-url "https://your-webhook-endpoint" --api-id 123 --api-hash "hash"
```

Or with env var:

```bash
export TG_SEND_LAST_N="2"
python3 telegram_channel_webhook.py
```

## Live mode (new messages only)

Make sure `TG_SEND_LAST_N` is unset or `0`.

```bash
unset TG_SEND_LAST_N
python3 telegram_channel_webhook.py
```

## Supply Chain Monitor script

`telegram_group_monitor.py` is preconfigured for:

- `https://t.me/+Pi4b85rUUKEzMjFk`

Run it:

```bash
export TG_API_ID="your_api_id"
export TG_API_HASH="your_api_hash"
export TG_PHONE="+1234567890"
export WEBHOOK_URL="https://your-webhook-endpoint"
python3 telegram_group_monitor.py
```

Test mode (last 2 messages):

```bash
export TG_SEND_LAST_N="2"
python3 telegram_group_monitor.py
```

## First login and 2FA

On first run, Telegram sends a login code.

- Interactive: script prompts for code.
- Non-interactive: set `TG_LOGIN_CODE`.
- If 2FA is enabled: set `TG_2FA_PASSWORD`.

## Webhook payload shape

```json
{
  "event": "telegram.new_message",
  "captured_at": "2026-05-14T17:38:33.621615+00:00",
  "chat": {
    "id": -1003912066166,
    "title": "Supply Chain Monitor",
    "username": null
  },
  "message": {
    "id": 1099,
    "text": "raw message text",
    "parsed": {
      "package": "node-ci-utils 2.1.4",
      "package_name": "node-ci-utils",
      "version": "2.1.4",
      "ecosystem": "npm",
      "summary": "...",
      "registry": "https://www.npmjs.com/package/node-ci-utils/v/2.1.4",
      "npm": {
        "registry_url": "https://registry.npmjs.org/node-ci-utils/2.1.4",
        "downloads_url": "https://api.npmjs.org/downloads/point/last-week/node-ci-utils",
        "metadata": {
          "name": "node-ci-utils",
          "version": "2.1.4"
        },
        "downloads_last_week": {
          "downloads": 0,
          "package": "node-ci-utils",
          "start": "2026-05-07",
          "end": "2026-05-13"
        }
      }
    },
    "date": "2026-05-14T16:01:45+00:00",
    "reply_to_msg_id": null,
    "views": 32,
    "forwards": 0
  },
  "sender": {
    "id": 3912066166,
    "username": null,
    "first_name": null,
    "last_name": null
  }
}
```

## Notes

- Telegram session is stored locally (`*.session` file) for reuse.
- Keep credentials secret.
- Rotate credentials if they were shared publicly.

## Local static-only malware pipeline (new)

This repo now includes a local/lab static-only analysis pipeline:

- `ingest_api.py`: webhook endpoint that accepts npm alert events.
- `worker.py`: background worker that analyzes npm package tarballs.
- `local_pipeline/`: queue/db/analyzer/notifier modules.
- `docker-compose.pipeline.yml`: local API + worker services.

### Pipeline flow

1. `telegram_group_monitor.py` sends event JSON to `POST /event/npm-alert`.
2. Ingest API validates request and enqueues a deduplicated job.
3. Worker fetches metadata and tarball from npm registry.
4. Worker unpacks tarball and runs static checks + IOC extraction.
5. Worker writes reports and sends notification to Slack/Telegram.

### Static analysis behavior

- Pull metadata from `https://registry.npmjs.org/{package}/{version}`.
- Pull weekly downloads from `https://api.npmjs.org/downloads/point/last-week/{package}`.
- Download `dist.tarball` and compute SHA256.
- Unpack and scan source files for suspicious patterns:
  - `child_process`, `eval`, `new Function`, base64 decode, curl/wget, raw URLs
  - install hooks (`preinstall`, `install`, `postinstall`)
- Extract basic IOCs: URLs, domains, IPv4 addresses.
- Optional AI investigator (Codex GPT-5.3) reviews extracted evidence and produces:
  - structured verdict JSON
  - detailed markdown investigation report

### Local setup (without Docker)

```bash
python3 -m pip install -r requirements-pipeline.txt
cp .env.pipeline.example .env.pipeline
set -a && source .env.pipeline && set +a
python3 ingest_api.py
```

In another terminal:

```bash
set -a && source .env.pipeline && set +a
python3 worker.py
```

Then run telegram monitor with the same env file loaded:

```bash
set -a && source .env.pipeline && set +a
python3 telegram_group_monitor.py
```

### Local setup (Docker)

```bash
cp .env.pipeline.example .env.pipeline
docker compose -f docker-compose.pipeline.yml up --build
```

### Ingest API contract

- Endpoint: `POST /event/npm-alert`
- Header: `x-api-token: <INGEST_API_TOKEN>` (if token configured)
- Expects parsed npm fields in payload:
  - `message.parsed.package_name`
  - `message.parsed.version`
  - `message.parsed.ecosystem = npm`

### Output artifacts

Generated under `pipeline_data/`:

- `pipeline_data/artifacts/job_<id>_<package>@<version>/package.tgz`
- `pipeline_data/reports/job_<id>_<package>@<version>/report_full.json`
- `pipeline_data/reports/job_<id>_<package>@<version>/report_summary.md`
- `pipeline_data/reports/job_<id>_<package>@<version>/report_ai_structured.json` (if AI enabled)
- `pipeline_data/reports/job_<id>_<package>@<version>/report_ai_detailed.md` (if AI enabled)
- `pipeline_data/reports/job_<id>_<package>@<version>/ai_manifest.json`
- `pipeline_data/reports/job_<id>_<package>@<version>/ai_coverage_report.json`
- `pipeline_data/reports/job_<id>_<package>@<version>/ai_batches.json`
- `pipeline_data/pipeline.log` (central log file)

### Logging

Set logging controls in `.env.pipeline`:

```bash
LOG_LEVEL="INFO"
LOG_FILE="./pipeline_data/pipeline.log"
```

Services log to both console and `pipeline.log` for easier debugging.

### Notifications

Optional env vars:

- `SLACK_WEBHOOK_URL`
- `SLACK_BOT_TOKEN`
- `SLACK_CHANNEL_ID`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Notification template includes:

- Package and version
- Tarball download URL
- Original alert summary
- Author
- Dependencies/devDependencies (count + first 10 names)
- Weekly downloads
- AI verdict and confidence

Attachment behavior:

- Telegram bot: sends message + files
  - `report_ai_detailed.md`
  - `report_full.json`
  - `ai_manifest.json`
  - `IOCs.md`
- Slack webhook only: message only
- Slack bot token + channel id: message + file uploads

### Enable AI investigator locally via OpenCode (recommended)

Set these in `.env.pipeline`:

```bash
AI_PROVIDER="opencode_local"
OPENCODE_CMD="opencode"
OPENCODE_ARGS="run"
OPENCODE_MODE="arg"
OPENCODE_TIMEOUT_SECONDS="900"
AI_MAX_FILES="12"
AI_MAX_CHARS_PER_FILE="5000"
AI_BATCH_SIZE="40"
AI_MAX_RETRIES="2"
AI_TARGET_EXTENSIONS=".js,.cjs,.mjs,.ts,.json,.sh"
```

Behavior:

- Worker invokes local `opencode` CLI in the unpacked package directory.
- Worker runs one detailed OpenCode prompt directly against the full extracted package directory.
- AI is instructed to detect obfuscation, deobfuscate statically, and analyze recovered behavior.
- AI output markdown is saved as the detailed forensic report.
- AI output is appended in `report_full.json` under `analysis.ai`.
- If local AI execution fails, deterministic static analysis still runs normally.

### Optional API fallback

If you want API mode instead of local OpenCode CLI:

```bash
AI_PROVIDER="openai_api"
OPENAI_API_KEY="<your_key>"
OPENAI_MODEL="openai/gpt-5.3-codex"
OPENAI_BASE_URL="https://api.openai.com/v1"
```
