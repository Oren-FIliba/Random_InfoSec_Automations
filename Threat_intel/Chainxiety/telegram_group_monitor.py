#!/usr/bin/env python3
import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from urllib.parse import quote

import requests
from telethon import TelegramClient, events


API_ID = int(os.environ["TG_API_ID"])
API_HASH = os.environ["TG_API_HASH"]
PHONE = os.environ.get("TG_PHONE")
LOGIN_CODE = os.environ.get("TG_LOGIN_CODE")
TWOFA_PASSWORD = os.environ.get("TG_2FA_PASSWORD")
SESSION_NAME = os.environ.get("TG_SESSION", "supply_chain_monitor")
GROUP_LINK = os.environ.get("TG_GROUP_LINK", "https://t.me/+Pi4b85rUUKEzMjFk")
WEBHOOK_URL = os.environ["WEBHOOK_URL"]
WEBHOOK_TIMEOUT = int(os.environ.get("WEBHOOK_TIMEOUT", "10"))
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "")
SEND_LAST_N = int(os.environ.get("TG_SEND_LAST_N", "0"))

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s telegram_group_monitor: %(message)s",
)
logger = logging.getLogger("telegram_group_monitor")


def to_iso8601(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def send_webhook(payload):
    headers = {"Content-Type": "application/json"}
    if WEBHOOK_TOKEN:
        headers["x-api-token"] = WEBHOOK_TOKEN

    response = requests.post(
        WEBHOOK_URL,
        data=json.dumps(payload),
        headers=headers,
        timeout=WEBHOOK_TIMEOUT,
    )
    response.raise_for_status()


def get_npm_metadata(package_name, version):
    if not package_name or not version:
        return None

    safe_name = quote(package_name, safe="@/")
    safe_version = quote(version, safe="")

    package_url = f"https://registry.npmjs.org/{safe_name}/{safe_version}"
    downloads_url = f"https://api.npmjs.org/downloads/point/last-week/{safe_name}"

    metadata = None
    downloads = None

    try:
        meta_resp = requests.get(package_url, timeout=WEBHOOK_TIMEOUT)
        if meta_resp.ok:
            metadata = meta_resp.json()
    except Exception:
        metadata = None

    try:
        dl_resp = requests.get(downloads_url, timeout=WEBHOOK_TIMEOUT)
        if dl_resp.ok:
            downloads = dl_resp.json()
    except Exception:
        downloads = None

    return {
        "registry_url": package_url,
        "downloads_url": downloads_url,
        "metadata": metadata,
        "downloads_last_week": downloads,
    }


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

    raw_package = package_match.group(1).strip() if package_match else None
    package_name = None
    version = None

    if raw_package:
        split_match = re.match(r"^(.+?)\s+([0-9A-Za-z][0-9A-Za-z._+-]*)$", raw_package)
        if split_match:
            package_name = split_match.group(1).strip()
            version = split_match.group(2).strip()
        else:
            package_name = raw_package

    parsed = {
        "package": raw_package,
        "package_name": package_name,
        "version": version,
        "ecosystem": ecosystem_match.group(1).strip() if ecosystem_match else None,
        "summary": summary_match.group(1).strip() if summary_match else None,
        "registry": registry_match.group(1).strip() if registry_match else None,
    }

    if any(parsed.values()):
        return parsed
    return None


async def build_payload(event, message, sender):
    parsed_alert = parse_alert_text(message.message)
    if parsed_alert and (parsed_alert.get("ecosystem") or "").lower() == "npm":
        npm_data = get_npm_metadata(
            parsed_alert.get("package_name"),
            parsed_alert.get("version"),
        )
        if npm_data:
            parsed_alert["npm"] = npm_data

    return {
        "event": event,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "chat": {
            "id": message.chat_id,
            "title": getattr(message.chat, "title", None),
            "username": getattr(message.chat, "username", None),
        },
        "message": {
            "id": message.id,
            "text": message.message,
            "parsed": parsed_alert,
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
    client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
    await client.connect()

    if not await client.is_user_authorized():
        if not PHONE:
            raise RuntimeError("Set TG_PHONE for first-time login.")
        await client.send_code_request(PHONE)
        code = LOGIN_CODE or input("Enter Telegram login code: ").strip()
        try:
            await client.sign_in(PHONE, code)
        except Exception as exc:
            if "SESSION_PASSWORD_NEEDED" in str(exc) and TWOFA_PASSWORD:
                await client.sign_in(password=TWOFA_PASSWORD)
            else:
                raise

    target = await client.get_entity(GROUP_LINK)
    me = await client.get_me()
    print(f"Logged in as: {me.username or me.id}")
    print(f"Monitoring: {getattr(target, 'title', str(target.id))}")
    print(f"Webhook: {WEBHOOK_URL}")
    logger.info("Connected and monitoring started")

    if SEND_LAST_N > 0:
        recent = []
        async for msg in client.iter_messages(target, limit=SEND_LAST_N):
            recent.append(msg)

        for msg in reversed(recent):
            sender = await msg.get_sender()
            payload = await build_payload("telegram.recent_message", msg, sender)
            send_webhook(payload)
            print(f"Forwarded recent message {msg.id}")
            logger.info("Forwarded recent message %s", msg.id)

        print(f"Sent last {len(recent)} messages. Exiting test mode.")
        return

    @client.on(events.NewMessage(chats=target))
    async def handler(event):
        message = event.message
        sender = await event.get_sender()
        payload = await build_payload("telegram.new_message", message, sender)

        try:
            send_webhook(payload)
            print(f"Forwarded message {message.id}")
            logger.info("Forwarded message %s", message.id)
        except Exception as exc:
            print(f"Failed to send webhook for message {message.id}: {exc}")
            logger.exception("Failed to forward message %s", message.id)

    print("Waiting for new messages...")
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
