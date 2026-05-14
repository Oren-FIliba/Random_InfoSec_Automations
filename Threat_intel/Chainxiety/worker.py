#!/usr/bin/env python3
import json
import time
import traceback

from local_pipeline.analyzer import analyze_package
from local_pipeline.config import DB_PATH
from local_pipeline.config import WORKER_POLL_INTERVAL
from local_pipeline.db import claim_next_job, complete_job, fail_job, init_db
from local_pipeline.logging_utils import setup_logging
from local_pipeline.notifier import notify


logger = setup_logging("worker")


def run_forever():
    init_db()
    logger.info("Worker started. Polling for jobs... DB=%s", DB_PATH)
    while True:
        job = claim_next_job()
        if not job:
            time.sleep(WORKER_POLL_INTERVAL)
            continue

        job_id = job["id"]
        package_name = job["package_name"]
        version = job["version"]
        payload = json.loads(job["payload_json"])
        logger.info("Processing job %s: %s@%s", job_id, package_name, version)

        try:
            report_json_path, summary_path, report_json = analyze_package(
                package_name=package_name,
                version=version,
                source_payload=payload,
                job_id=job_id,
            )
            complete_job(job_id, report_json_path, summary_path)
            notify(report_json, report_json.get("artifacts") or {})
            logger.info("Job %s done", job_id)
        except Exception as exc:
            err = f"{exc}\n{traceback.format_exc()}"
            fail_job(job_id, err)
            logger.exception("Job %s failed: %s", job_id, exc)


if __name__ == "__main__":
    run_forever()
