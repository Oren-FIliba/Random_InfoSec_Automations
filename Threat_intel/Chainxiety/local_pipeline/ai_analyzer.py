import json
import shlex
import subprocess
import tempfile

import requests

from .config import (
    AI_PROVIDER,
    OPENCODE_ARGS,
    OPENCODE_CMD,
    OPENCODE_MODE,
    OPENCODE_TIMEOUT_SECONDS,
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    OPENAI_MODEL,
    WORKER_TIMEOUT_SECONDS,
)
from .logging_utils import setup_logging


logger = setup_logging("ai_analyzer")


def _extract_output_text(response_json):
    texts = []
    for item in response_json.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in ("output_text", "text") and content.get("text"):
                texts.append(content["text"])
    if texts:
        return "\n".join(texts).strip()
    return response_json.get("output_text", "").strip()


def run_ai_prompt(prompt_obj, package_root=None):
    prompt_text = json.dumps(prompt_obj)

    if AI_PROVIDER == "opencode_local":
        return _run_local_opencode(prompt_text, package_root=package_root)

    if not OPENAI_API_KEY:
        logger.info("AI skipped: OPENAI_API_KEY not set for provider=%s", AI_PROVIDER)
        return None

    url = f"{OPENAI_BASE_URL}/responses"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": OPENAI_MODEL,
        "input": prompt_text,
    }

    resp = requests.post(url, headers=headers, json=body, timeout=WORKER_TIMEOUT_SECONDS)
    resp.raise_for_status()
    text = _extract_output_text(resp.json())
    if not text:
        return None

    json_block = None
    md_block = None

    if "```json" in text:
        json_block = text.split("```json", 1)[1].split("```", 1)[0].strip()
    if "```markdown" in text:
        md_block = text.split("```markdown", 1)[1].split("```", 1)[0].strip()
    elif "```md" in text:
        md_block = text.split("```md", 1)[1].split("```", 1)[0].strip()

    parsed_json = None
    if json_block:
        try:
            parsed_json = json.loads(json_block)
        except Exception:
            parsed_json = None

    return {
        "model": OPENAI_MODEL,
        "raw_text": text,
        "structured": parsed_json,
        "markdown": md_block,
    }


def run_ai_static_analysis(package_name, version, analysis_context, package_root=None, report_output_path=None):
    logger.info("Running AI static analysis for %s@%s", package_name, version)
    prompt = {
        "task": "Perform full static malware analysis on the entire npm package source tree.",
        "package": {"name": package_name, "version": version},
        "evidence": analysis_context,
        "instructions": [
            "Inspect all files recursively from the current working directory.",
            "If code is obfuscated, statically deobfuscate and analyze recovered behavior.",
            "Produce a detailed technical forensic report in markdown.",
            "Include verdict, confidence, behavior breakdown, IOC table, and remediation.",
            "Do not invent facts. Mark uncertainty explicitly.",
            "Return markdown report text.",
        ],
    }
    if report_output_path:
        prompt["instructions"].append(
            f"Write the full markdown report to this exact path: {report_output_path}"
        )
        prompt["instructions"].append(
            "After writing the file, also print the same markdown report in your output."
        )
    return run_ai_prompt(prompt, package_root=package_root)


def _run_local_opencode(prompt_text, package_root=None):
    cmd = [OPENCODE_CMD] + shlex.split(OPENCODE_ARGS)
    mode = OPENCODE_MODE.lower().strip()
    package_path = package_root or "."
    ai_prompt = (
        "Perform full static malware analysis for this npm package source tree. "
        f"Package path: {package_path}. "
        "Inspect ALL source files under this package path recursively. "
        "When code is obfuscated, deobfuscate it statically and analyze recovered logic. "
        "Produce a full forensic technical report in markdown with sections for verdict, "
        "confidence, behavior analysis, file-by-file findings, IOCs, deobfuscation details, "
        "and remediation recommendations. "
        "Return exactly two fenced blocks: first ```json then ```markdown.\n\n"
        f"Evidence JSON:\n{prompt_text}"
    )

    try:
        if mode == "stdin":
            result = subprocess.run(
                cmd,
                input=ai_prompt,
                capture_output=True,
                text=True,
                timeout=OPENCODE_TIMEOUT_SECONDS,
                check=True,
                cwd=package_root,
            )
        elif mode == "arg":
            result = subprocess.run(
                cmd + [ai_prompt],
                capture_output=True,
                text=True,
                timeout=OPENCODE_TIMEOUT_SECONDS,
                check=True,
                cwd=package_root,
            )
        elif mode == "file":
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=True) as f:
                f.write(ai_prompt)
                f.flush()
                result = subprocess.run(
                    cmd + [f.name],
                    capture_output=True,
                    text=True,
                    timeout=OPENCODE_TIMEOUT_SECONDS,
                    check=True,
                    cwd=package_root,
                )
        else:
            raise RuntimeError(f"Unsupported OPENCODE_MODE: {OPENCODE_MODE}")
    except Exception as exc:
        logger.exception("Local OpenCode execution failed")
        return {
            "model": "opencode_local",
            "raw_text": f"Local opencode execution failed: {exc}",
            "structured": None,
            "markdown": None,
        }

    text = (result.stdout or "").strip()
    if not text:
        text = (result.stderr or "").strip()

    if "```json" not in text and "```markdown" not in text and "```md" not in text:
        return {
            "model": "opencode_local",
            "raw_text": text,
            "structured": None,
            "markdown": text,
        }

    json_block = None
    md_block = None
    if "```json" in text:
        json_block = text.split("```json", 1)[1].split("```", 1)[0].strip()
    if "```markdown" in text:
        md_block = text.split("```markdown", 1)[1].split("```", 1)[0].strip()
    elif "```md" in text:
        md_block = text.split("```md", 1)[1].split("```", 1)[0].strip()

    parsed_json = None
    if json_block:
        try:
            parsed_json = json.loads(json_block)
        except Exception:
            parsed_json = None

    return {
        "model": "opencode_local",
        "raw_text": text,
        "structured": parsed_json,
        "markdown": md_block,
    }
