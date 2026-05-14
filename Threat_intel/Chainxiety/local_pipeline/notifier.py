import json
import os

import requests

from .config import (
    SLACK_BOT_TOKEN,
    SLACK_CHANNEL_ID,
    SLACK_WEBHOOK_URL,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
)
from .logging_utils import setup_logging


logger = setup_logging("notifier")


def _first_n_keys(d, n=10):
    if not isinstance(d, dict):
        return []
    return list(sorted(d.keys()))[:n]


def _ai_verdict_fields(report_json):
    analysis = report_json.get("analysis") or {}
    structured = (analysis.get("ai") or {}).get("structured") or {}
    verdict = (
        structured.get("verdict") or analysis.get("ai_structured_verdict") or "n/a"
    )
    confidence = (
        structured.get("confidence")
        or analysis.get("ai_structured_confidence")
        or "n/a"
    )
    verdict_desc = structured.get("summary") or "No AI summary provided"
    confidence_desc = "Model confidence based on available static evidence"
    return verdict, verdict_desc, confidence, confidence_desc


def _build_alert_text(report_json):
    pkg = report_json.get("package") or {}
    reg = report_json.get("registry") or {}
    alert = report_json.get("source_alert") or {}
    verdict, verdict_desc, confidence, confidence_desc = _ai_verdict_fields(report_json)

    deps = pkg.get("dependencies") or {}
    dev_deps = pkg.get("dev_dependencies") or {}
    deps_head = _first_n_keys(deps, 10)
    dev_deps_head = _first_n_keys(dev_deps, 10)
    deps_more = max(0, len(deps) - len(deps_head))
    dev_more = max(0, len(dev_deps) - len(dev_deps_head))

    weekly = (reg.get("downloads_last_week") or {}).get("downloads")
    dep_line = ", ".join(deps_head) if deps_head else "None"
    dev_line = ", ".join(dev_deps_head) if dev_deps_head else "None"
    if deps_more:
        dep_line += f" (+{deps_more} more)"
    if dev_more:
        dev_line += f" (+{dev_more} more)"

    text = "\n\n".join(
        [
            "🚨 *Supply Chain Alert — Static Malware Analysis*",
            "\n".join(
                [
                    f"📦 *Package*\n`{pkg.get('name')}@{pkg.get('version')}`",
                    f"📥 *Tarball Download*\n{reg.get('tarball_url')}",
                    f"📝 *Summary*\n{alert.get('summary') or 'N/A'}",
                    f"👤 *\nAuthor*\n{pkg.get('author') or 'Unknown'}",
                    f"📚 *Dependencies ({pkg.get('dependencies_count', 0)})*\n{dep_line}",
                    f"🛠️ *DevDependencies ({pkg.get('dev_dependencies_count', 0)})*\n{dev_line}",
                    f"📈 *Weekly Downloads*\n{weekly}",
                ]
            ),
            "\n".join(
                [
                    f"🤖 *AI Verdict*\n`{verdict}`",
                    f"ℹ️ {verdict_desc}",
                ]
            ),
            "\n".join(
                [
                    f"🎯 *Confidence*\n`{confidence}`",
                    f"📌 {confidence_desc}",
                ]
            ),
        ]
    )

    return text


def _slack_upload_file(path, title, initial_comment=""):
    if not (SLACK_BOT_TOKEN and SLACK_CHANNEL_ID):
        return False
    if not os.path.exists(path):
        logger.warning("Slack upload skipped missing file: %s", path)
        return False

    with open(path, "rb") as f:
        resp = requests.post(
            "https://slack.com/api/files.upload",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            data={
                "channels": SLACK_CHANNEL_ID,
                "title": title,
                "initial_comment": initial_comment,
            },
            files={"file": f},
            timeout=30,
        )
    data = resp.json()
    ok = bool(data.get("ok"))
    if not ok:
        logger.warning("Slack file upload failed for %s: %s", path, data)
    return ok


def _notify_slack(text, attachments):
    if SLACK_WEBHOOK_URL:
        try:
            requests.post(
                SLACK_WEBHOOK_URL, json={"text": text}, timeout=15
            ).raise_for_status()
            logger.info("Slack webhook notification sent")
        except Exception as exc:
            logger.exception("Slack webhook notify failed: %s", exc)

    if SLACK_BOT_TOKEN and SLACK_CHANNEL_ID:
        try:
            msg = requests.post(
                "https://slack.com/api/chat.postMessage",
                headers={
                    "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                    "Content-Type": "application/json",
                },
                json={"channel": SLACK_CHANNEL_ID, "text": text},
                timeout=15,
            )
            logger.info("Slack bot message response: %s", msg.status_code)
        except Exception as exc:
            logger.exception("Slack bot message failed: %s", exc)

        for p in attachments:
            _slack_upload_file(p, os.path.basename(p))


def _telegram_send_document(path, caption=""):
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return
    if not os.path.exists(path):
        logger.warning("Telegram upload skipped missing file: %s", path)
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    with open(path, "rb") as f:
        requests.post(
            url,
            data={
                "chat_id": TELEGRAM_CHAT_ID,
                "caption": caption[:1000] if caption else "",
            },
            files={"document": f},
            timeout=30,
        ).raise_for_status()


def _notify_telegram(text, attachments):
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(
            url,
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=15,
        ).raise_for_status()
        logger.info("Telegram message notification sent")
    except Exception as exc:
        logger.exception("Telegram message failed: %s", exc)

    for p in attachments:
        try:
            _telegram_send_document(p)
            logger.info("Telegram attachment sent: %s", p)
        except Exception as exc:
            logger.exception("Telegram attachment failed %s: %s", p, exc)


def notify(report_json, artifacts):
    text = _build_alert_text(report_json)
    attachment_paths = [
        artifacts.get("report_ai_detailed_md"),
        artifacts.get("report_full_json"),
        artifacts.get("ai_manifest_json"),
        artifacts.get("iocs_md"),
    ]
    attachment_paths = [p for p in attachment_paths if p]

    _notify_slack(text, attachment_paths)
    _notify_telegram(text, attachment_paths)
