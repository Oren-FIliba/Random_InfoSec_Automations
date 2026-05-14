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
export TG_API_ID="31751245"
export TG_API_HASH="your_api_hash"
export TG_PHONE="+972.."
export WEBHOOK_URL="https://your-webhook-endpoint"
export TG_SOURCE="https://t.me..."
python3 telegram_channel_webhook.py
```

### Option B: CLI arguments

```bash
python3 telegram_channel_webhook.py \
  --api-id 31755259 \
  --api-hash "your_api_hash" \
  --phone "+972..." \
  --source "https://t.me/..." \
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
      "ecosystem": "npm",
      "summary": "...",
      "registry": "https://www.npmjs.com/package/node-ci-utils/v/2.1.4"
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
