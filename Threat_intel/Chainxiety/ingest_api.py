#!/usr/bin/env python3
import hashlib

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request

from local_pipeline.config import INGEST_API_HOST, INGEST_API_PORT, INGEST_API_TOKEN
from local_pipeline.db import enqueue_job, init_db
from local_pipeline.logging_utils import setup_logging


app = FastAPI(title="NPM Alert Ingest API", version="0.1.0")
logger = setup_logging("ingest_api")


def extract_package_fields(payload):
    parsed = ((payload.get("message") or {}).get("parsed") or {})
    package_name = parsed.get("package_name")
    version = parsed.get("version")
    ecosystem = (parsed.get("ecosystem") or "").lower()
    if ecosystem != "npm":
        return None, None
    return package_name, version


def dedupe_key(payload, package_name, version):
    chat_id = ((payload.get("chat") or {}).get("id"))
    message_id = ((payload.get("message") or {}).get("id"))
    raw = f"{chat_id}:{message_id}:{package_name}:{version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@app.on_event("startup")
def startup_event():
    init_db()
    logger.info("Ingest API started")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/event/npm-alert")
async def npm_alert(request: Request, x_api_token: str = Header(default="")):
    if INGEST_API_TOKEN and x_api_token != INGEST_API_TOKEN:
        logger.warning("Rejected request: invalid x-api-token")
        raise HTTPException(status_code=401, detail="Invalid token")

    payload = await request.json()
    package_name, version = extract_package_fields(payload)
    if not package_name or not version:
        logger.warning("Rejected payload: missing npm package_name/version")
        raise HTTPException(status_code=400, detail="Missing npm package_name/version in payload")

    chat_id = ((payload.get("chat") or {}).get("id"))
    message_id = ((payload.get("message") or {}).get("id"))
    key = dedupe_key(payload, package_name, version)
    inserted = enqueue_job(key, payload, package_name, version, chat_id, message_id)

    if inserted:
        logger.info(
            "Enqueued job %s@%s chat=%s msg=%s key=%s",
            package_name,
            version,
            chat_id,
            message_id,
            key[:12],
        )
    else:
        logger.info(
            "Duplicate ignored %s@%s chat=%s msg=%s key=%s",
            package_name,
            version,
            chat_id,
            message_id,
            key[:12],
        )

    return {
        "accepted": inserted,
        "dedupe_key": key,
        "package_name": package_name,
        "version": version,
    }


if __name__ == "__main__":
    uvicorn.run(app, host=INGEST_API_HOST, port=INGEST_API_PORT)
