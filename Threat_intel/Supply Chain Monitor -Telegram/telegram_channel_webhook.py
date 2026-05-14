#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import re
from datetime import datetime, timezone

import requests
from telethon import TelegramClient, events


def to_iso8601(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def parse_alert_text(text):
    if not text:
        return None

    package_match = re.search(r"^Package:\s*(.+)$", text, re.MULTILINE)
    ecosystem_match = re.search(r"^Ecosystem:\s*(.+)$", text, re.MULTILINE)
    registry_match = re.search(r"^🔗\s*Registry:\s*(.+)$", text, re.MULTILINE)
    summary_match = re.search(
        r"^Summary:\s*\n(.*?)(?:\n\s*🔗\s*Registry:|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )

    parsed = {
        "package": package_match.group(1).strip() if package_match else None,
        "ecosystem": ecosystem_match.group(1).strip() if ecosystem_match else None,
        "summary": summary_match.group(1).strip() if summary_match else None,
        "registry": registry_match.group(1).strip() if registry_match else None,
    }
    return parsed if any(parsed.values()) else None


def send_webhook(webhook_url, webhook_timeout, payload):
    response = requests.post(
        webhook_url,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=webhook_timeout,
    )
    response.raise_for_status()


def load_config():
    parser = argparse.ArgumentParser(
        description="Monitor a Telegram channel/group and forward messages to a webhook"
    )
    parser.add_argument("--api-id", type=int, default=os.environ.get("TG_API_ID"))
    parser.add_argument("--api-hash", default=os.environ.get("TG_API_HASH"))
    parser.add_argument("--phone", default=os.environ.get("TG_PHONE"))
    parser.add_argument("--login-code", default=os.environ.get("TG_LOGIN_CODE"))
    parser.add_argument("--twofa-password", default=os.environ.get("TG_2FA_PASSWORD"))
    parser.add_argument("--session", default=os.environ.get("TG_SESSION", "tg_monitor"))
    parser.add_argument(
        "--source",
        default=os.environ.get("TG_SOURCE"),
        help="Channel/group @username, t.me link, invite link, or numeric ID",
    )
    parser.add_argument("--webhook-url", default=os.environ.get("WEBHOOK_URL"))
    parser.add_argument(
        "--webhook-timeout", type=int, default=int(os.environ.get("WEBHOOK_TIMEOUT", "10"))
    )
    parser.add_argument(
        "--send-last-n",
        type=int,
        default=int(os.environ.get("TG_SEND_LAST_N", "0")),
        help="Send last N existing messages, then exit",
    )
    args = parser.parse_args()

    required = {
        "api_id": args.api_id,
        "api_hash": args.api_hash,
        "source": args.source,
        "webhook_url": args.webhook_url,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RuntimeError(f"Missing required settings: {', '.join(missing)}")

    return args


def build_payload(event_name, message, sender):
    return {
        "event": event_name,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "chat": {
            "id": message.chat_id,
            "title": getattr(message.chat, "title", None),
            "username": getattr(message.chat, "username", None),
        },
        "message": {
            "id": message.id,
            "text": message.message,
            "parsed": parse_alert_text(message.message),
            "date": to_iso8601(message.date),
            "reply_to_msg_id": getattr(message, "reply_to_msg_id", None),
            "views": getattr(message, "views", None),
            "forwards": getattr(message, "forwards", None),
        },
        "sender": {
            "id": getattr(sender, "id", None),
            "username": getattr(sender, "username", None),
            "first_name": getattr(sender, "first_name", None),
            "last_name": getattr(sender, "last_name", None),
        },
    }


async def main():
    cfg = load_config()
    client = TelegramClient(cfg.session, int(cfg.api_id), cfg.api_hash)
    await client.connect()

    if not await client.is_user_authorized():
        if not cfg.phone:
            raise RuntimeError("Set --phone or TG_PHONE for first-time login.")
        await client.send_code_request(cfg.phone)
        code = cfg.login_code or input("Enter Telegram login code: ").strip()
        try:
            await client.sign_in(cfg.phone, code)
        except Exception as exc:
            if "SESSION_PASSWORD_NEEDED" in str(exc) and cfg.twofa_password:
                await client.sign_in(password=cfg.twofa_password)
            else:
                raise

    target = await client.get_entity(cfg.source)
    me = await client.get_me()
    print(f"Logged in as: {me.username or me.id}")
    print(f"Monitoring: {getattr(target, 'title', str(target.id))}")
    print(f"Webhook: {cfg.webhook_url}")

    if cfg.send_last_n > 0:
        recent = []
        async for msg in client.iter_messages(target, limit=cfg.send_last_n):
            recent.append(msg)

        for msg in reversed(recent):
            sender = await msg.get_sender()
            payload = build_payload("telegram.recent_message", msg, sender)
            send_webhook(cfg.webhook_url, cfg.webhook_timeout, payload)
            print(f"Forwarded recent message {msg.id}")

        print(f"Sent last {len(recent)} messages. Exiting test mode.")
        return

    @client.on(events.NewMessage(chats=target))
    async def handler(event):
        message = event.message
        sender = await event.get_sender()
        payload = build_payload("telegram.new_message", message, sender)
        try:
            send_webhook(cfg.webhook_url, cfg.webhook_timeout, payload)
            print(f"Forwarded message {message.id}")
        except Exception as exc:
            print(f"Failed to send webhook for message {message.id}: {exc}")

    print("Waiting for new messages...")
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
