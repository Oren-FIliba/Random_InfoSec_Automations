import hashlib
import json
import os
import re
import tarfile
import tempfile
from datetime import datetime, timezone
from urllib.parse import quote

import requests

from .ai_analyzer import run_ai_static_analysis
from .config import (
    AI_BATCH_SIZE,
    AI_MAX_RETRIES,
    AI_MAX_CHARS_PER_FILE,
    AI_MAX_FILES,
    AI_TARGET_EXTENSIONS,
    ARTIFACTS_DIR,
    REPORTS_DIR,
    TMP_DIR,
    WORKER_TIMEOUT_SECONDS,
)
from .logging_utils import setup_logging


logger = setup_logging("analyzer")


SUSPICIOUS_PATTERNS = {
    "child_process": r"\bchild_process\b",
    "eval": r"\beval\s*\(",
    "function_constructor": r"new\s+Function\s*\(",
    "base64_decode": r"Buffer\.from\([^\)]*,\s*['\"]base64['\"]\)",
    "curl_wget": r"\b(curl|wget)\b",
    "http_raw": r"\bhttps?://",
    "install_scripts": r"\b(preinstall|postinstall|install)\b",
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _ensure_dirs():
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(TMP_DIR, exist_ok=True)


def _get_npm_metadata(package_name, version):
    safe_name = quote(package_name, safe="@/")
    safe_version = quote(version, safe="")
    package_url = f"https://registry.npmjs.org/{safe_name}/{safe_version}"
    downloads_url = f"https://api.npmjs.org/downloads/point/last-week/{safe_name}"

    resp = requests.get(package_url, timeout=WORKER_TIMEOUT_SECONDS)
    resp.raise_for_status()
    metadata = resp.json()

    downloads = None
    try:
        dresp = requests.get(downloads_url, timeout=WORKER_TIMEOUT_SECONDS)
        if dresp.ok:
            downloads = dresp.json()
    except Exception:
        downloads = None

    return metadata, downloads, package_url, downloads_url


def _collect_iocs_from_text(text):
    urls = sorted(set(re.findall(r"https?://[^\s'\"<>]+", text)))
    domains = sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)))
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    return {"urls": urls, "domains": domains, "ips": ips}


def _obfuscation_signals(content):
    checks = {
        "eval": r"\beval\s*\(",
        "function_constructor": r"new\s+Function\s*\(",
        "hex_escapes": r"\\x[0-9a-fA-F]{2}",
        "unicode_escapes": r"\\u[0-9a-fA-F]{4}",
        "charcode": r"fromCharCode\s*\(",
        "atob": r"\batob\s*\(",
        "long_base64": r"[A-Za-z0-9+/]{120,}={0,2}",
        "array_decoder": r"\[[^\]]{20,}\]\s*\[\s*\w+\s*\]",
    }
    matched = [name for name, pat in checks.items() if re.search(pat, content)]
    return matched


def _scan_files(unpacked_dir):
    findings = []
    all_iocs = {"urls": set(), "domains": set(), "ips": set()}
    files_scanned = 0
    obfuscation = []

    for root, _, files in os.walk(unpacked_dir):
        for name in files:
            path = os.path.join(root, name)
            rel_path = os.path.relpath(path, unpacked_dir)
            if os.path.getsize(path) > 1_500_000:
                continue

            if not name.endswith((".js", ".cjs", ".mjs", ".json", ".ts", ".sh")):
                continue

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            files_scanned += 1
            for key, pattern in SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({"file": rel_path, "rule": key})

            signals = _obfuscation_signals(content)
            if signals:
                obfuscation.append({"file": rel_path, "signals": signals, "score": len(signals)})

            iocs = _collect_iocs_from_text(content)
            all_iocs["urls"].update(iocs["urls"])
            all_iocs["domains"].update(iocs["domains"])
            all_iocs["ips"].update(iocs["ips"])

    return {
        "files_scanned": files_scanned,
        "findings": findings,
        "iocs": {k: sorted(v) for k, v in all_iocs.items()},
        "obfuscation": sorted(obfuscation, key=lambda x: x["score"], reverse=True),
    }


def _build_file_manifest(package_root):
    manifest = []
    for root, _, files in os.walk(package_root):
        for name in files:
            rel_path = os.path.relpath(os.path.join(root, name), package_root)
            if not rel_path.endswith(AI_TARGET_EXTENSIONS):
                continue
            abs_path = os.path.join(package_root, rel_path)
            try:
                size = os.path.getsize(abs_path)
            except OSError:
                continue
            manifest.append(
                {
                    "path": rel_path,
                    "size": size,
                    "sha256": _sha256_file(abs_path),
                }
            )
    manifest.sort(key=lambda x: x["path"])
    return manifest


def _read_file_excerpt(base_dir, rel_path, max_chars=6000):
    abs_path = os.path.join(base_dir, rel_path)
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_chars)
    except Exception:
        return ""


def _chunk_list(items, size):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _validate_batch_result(batch_files, ai_result):
    structured = (ai_result or {}).get("structured") or {}
    reviewed = structured.get("files_reviewed") or []
    if not isinstance(reviewed, list):
        reviewed = []
    expected = set(batch_files)
    got = set(str(x) for x in reviewed)
    missing = sorted(expected - got)
    return {
        "ok": len(missing) == 0,
        "missing": missing,
        "reviewed": sorted(got),
    }


def _run_ai_full_forensics(package_name, version, package_root, manifest, scan, install_scripts):
    batches = list(_chunk_list(manifest, AI_BATCH_SIZE))
    batch_results = []

    for idx, batch in enumerate(batches, start=1):
        batch_id = f"batch_{idx:03d}"
        batch_files = [item["path"] for item in batch]
        snippets = [
            {"file": item["path"], "snippet": _read_file_excerpt(package_root, item["path"])[:AI_MAX_CHARS_PER_FILE]}
            for item in batch
        ]

        prompt_obj = {
            "task": "Full forensic static malware analysis for one batch of package files.",
            "package": {"name": package_name, "version": version},
            "batch_id": batch_id,
            "required_files": batch_files,
            "requirements": {
                "must_review_all_required_files": True,
                "obfuscation_handling": [
                    "Detect obfuscation techniques",
                    "Deobfuscate statically as far as possible",
                    "Analyze recovered behavior",
                    "List unresolved portions",
                ],
                "output_json_schema": {
                    "batch_id": "string",
                    "files_reviewed": ["string"],
                    "per_file_analysis": [
                        {
                            "file": "string",
                            "risk_level": "low|medium|high",
                            "obfuscation_detected": "boolean",
                            "obfuscation_techniques": ["string"],
                            "deobfuscation_steps": ["string"],
                            "behavior_summary": "string",
                            "evidence": ["string"],
                            "iocs": {
                                "urls": ["string"],
                                "domains": ["string"],
                                "ips": ["string"],
                                "commands": ["string"],
                                "file_paths": ["string"],
                            },
                        }
                    ],
                    "batch_iocs_aggregated": "object",
                    "batch_conclusion": "string",
                },
            },
            "context": {
                "install_scripts": install_scripts,
                "deterministic_findings": [f for f in scan["findings"] if f.get("file") in batch_files],
                "deterministic_obfuscation": [o for o in scan["obfuscation"] if o.get("file") in batch_files],
                "file_snippets": snippets,
            },
            "instructions": [
                "Inspect all required files recursively from local tree, not snippets only.",
                "Do not skip files. Include each required file in files_reviewed.",
                "Return exactly two fenced blocks: first json, second markdown.",
                "No claim without evidence from file content.",
            ],
        }

        ai_result = None
        validation = None
        for attempt in range(1, AI_MAX_RETRIES + 2):
            ai_result = run_ai_static_analysis(package_name, version, prompt_obj, package_root=package_root)
            validation = _validate_batch_result(batch_files, ai_result)
            if validation["ok"]:
                break
            logger.warning("AI batch %s attempt %s incomplete; missing=%s", batch_id, attempt, len(validation["missing"]))

        batch_results.append(
            {
                "batch_id": batch_id,
                "files": batch_files,
                "validation": validation,
                "ai": ai_result,
            }
        )

    expected = {item["path"] for item in manifest}
    reviewed = set()
    for batch in batch_results:
        structured = ((batch.get("ai") or {}).get("structured") or {})
        for p in structured.get("files_reviewed") or []:
            reviewed.add(str(p))

    missing = sorted(expected - reviewed)
    coverage = {
        "files_expected": len(expected),
        "files_reviewed": len(reviewed),
        "coverage_percent": round((len(reviewed) / len(expected) * 100), 2) if expected else 0.0,
        "missing_files": missing,
        "complete": len(missing) == 0,
    }

    synthesis_prompt = {
        "task": "Generate final forensic static malware report from batch analyses.",
        "package": {"name": package_name, "version": version},
        "coverage": coverage,
        "requirements": {
            "must_include": [
                "Full technical breakdown",
                "Executive summary",
                "Consolidated IOC table",
                "Obfuscation and deobfuscation findings",
                "Confidence and limitations",
                "Response recommendations",
            ],
            "output_json_schema": {
                "verdict": "malicious|suspicious|likely_benign|inconclusive",
                "confidence": "low|medium|high",
                "summary": "string",
                "key_behaviors": ["string"],
                "iocs": {
                    "urls": ["string"],
                    "domains": ["string"],
                    "ips": ["string"],
                    "commands": ["string"],
                    "file_paths": ["string"],
                },
                "analysis_completeness": {
                    "coverage_percent": "number",
                    "files_expected": "number",
                    "files_reviewed": "number",
                    "missing_files_count": "number",
                },
                "recommendations": ["string"],
            },
        },
        "context": {
            "deterministic_scan": scan,
            "batch_structured_outputs": [((b.get("ai") or {}).get("structured") or {}) for b in batch_results],
        },
        "instructions": [
            "If coverage is incomplete, clearly mark report as incomplete.",
            "Return exactly two fenced blocks: first json, second markdown.",
        ],
    }
    synthesis = run_ai_static_analysis(package_name, version, synthesis_prompt, package_root=package_root)

    return {
        "coverage": coverage,
        "batches": batch_results,
        "synthesis": synthesis,
    }


def _collect_file_snippets(unpacked_dir, findings):
    seen = set()
    targets = []

    for finding in findings:
        fp = finding.get("file")
        if fp and fp not in seen:
            targets.append(fp)
            seen.add(fp)

    package_json = os.path.join("package", "package.json")
    if package_json not in seen:
        targets.insert(0, package_json)

    snippets = []
    for rel_path in targets[:AI_MAX_FILES]:
        abs_path = os.path.join(unpacked_dir, rel_path)
        if not os.path.exists(abs_path):
            continue
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(AI_MAX_CHARS_PER_FILE)
        except Exception:
            continue
        snippets.append({"file": rel_path, "snippet": content})
    return snippets


def _extract_install_scripts(unpacked_dir):
    pkg_json = os.path.join(unpacked_dir, "package", "package.json")
    if not os.path.exists(pkg_json):
        return {}
    try:
        with open(pkg_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        scripts = (data.get("scripts") or {})
        return {k: scripts.get(k) for k in ["preinstall", "install", "postinstall"] if k in scripts}
    except Exception:
        return {}


def _extract_package_metadata(metadata):
    author = metadata.get("author")
    if isinstance(author, dict):
        author = author.get("name") or author.get("email") or str(author)
    elif author is not None:
        author = str(author)

    dependencies = metadata.get("dependencies") or {}
    dev_dependencies = metadata.get("devDependencies") or {}
    if not isinstance(dependencies, dict):
        dependencies = {}
    if not isinstance(dev_dependencies, dict):
        dev_dependencies = {}

    return {
        "author": author,
        "dependencies": dependencies,
        "dev_dependencies": dev_dependencies,
    }


def _source_alert_summary(source_payload):
    parsed = ((source_payload or {}).get("message") or {}).get("parsed") or {}
    return parsed.get("summary")


def _extract_ai_iocs(ai_result):
    structured = (ai_result or {}).get("structured") or {}
    iocs = structured.get("iocs") or {}
    if not isinstance(iocs, dict):
        iocs = {}
    return {
        "urls": sorted(set(iocs.get("urls") or [])),
        "domains": sorted(set(iocs.get("domains") or [])),
        "ips": sorted(set(iocs.get("ips") or [])),
        "commands": sorted(set(iocs.get("commands") or [])),
        "file_paths": sorted(set(iocs.get("file_paths") or [])),
    }


def _extract_iocs_from_markdown(md_text):
    if not md_text:
        return {"urls": [], "domains": [], "ips": [], "commands": [], "file_paths": []}

    def _extract_section(text, title_patterns):
        lines = text.splitlines()
        start = None
        for i, line in enumerate(lines):
            ll = line.strip().lower()
            if ll.startswith("#"):
                for p in title_patterns:
                    if p in ll:
                        start = i + 1
                        break
            if start is not None:
                break
        if start is None:
            return ""
        collected = []
        for line in lines[start:]:
            ll = line.strip().lower()
            if ll.startswith("#"):
                break
            collected.append(line)
        return "\n".join(collected)

    ioc_section = _extract_section(md_text, ["indicator", "ioc"])
    network_section = _extract_section(md_text, ["network", "c2", "domain", "url"])
    commands_section = _extract_section(md_text, ["command", "execution", "shell"])
    files_section = _extract_section(md_text, ["file", "path", "artifact"])

    primary = "\n".join([ioc_section, network_section]).strip() or md_text

    urls = sorted(set(re.findall(r"https?://[^\s)\]>\"']+", primary)))
    domains = sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", primary)))
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", primary)))

    cmd_matches = re.findall(r"`([^`\n]{3,200})`", commands_section or md_text)
    commands = []
    for c in cmd_matches:
        lc = c.lower()
        if any(x in lc for x in ["curl ", "wget ", "bash ", "sh ", "node ", "npm ", "npx ", "chmod ", "python "]):
            commands.append(c.strip())
    commands = sorted(set(commands))

    file_path_matches = re.findall(r"\b(?:[\w.-]+/)+[\w.-]+\b", files_section or md_text)
    file_paths = sorted(set(p for p in file_path_matches if "/" in p and not p.startswith("http")))

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "commands": commands,
        "file_paths": file_paths,
    }


def _write_iocs_md(iocs_path, ai_iocs):
    def _render(items):
        return "\n".join(f"- `{x}`" for x in items) if items else "- None"

    merged_urls = sorted(set(ai_iocs.get("urls") or []))
    merged_domains = sorted(set(ai_iocs.get("domains") or []))
    merged_ips = sorted(set(ai_iocs.get("ips") or []))

    content = "\n".join(
        [
            "# IOCs",
            "",
            "## URLs",
            _render(merged_urls),
            "",
            "## Domains",
            _render(merged_domains),
            "",
            "## IPs",
            _render(merged_ips),
            "",
            "## Commands (AI)",
            _render(ai_iocs.get("commands") or []),
            "",
            "## File Paths (AI)",
            _render(ai_iocs.get("file_paths") or []),
            "",
            "## Notes",
            "- All IOCs are extracted from report_ai_detailed.md.",
        ]
    )
    with open(iocs_path, "w", encoding="utf-8") as f:
        f.write(content)


def _compute_verdict(findings, install_scripts):
    score = len(findings)
    if install_scripts:
        score += 3

    if score >= 12:
        return "high_risk", score
    if score >= 6:
        return "medium_risk", score
    return "low_risk", score


def analyze_package(package_name, version, source_payload, job_id):
    _ensure_dirs()
    run_key = f"job_{job_id}_{package_name.replace('/', '_')}@{version}"
    artifact_dir = os.path.join(ARTIFACTS_DIR, run_key)
    report_dir = os.path.join(REPORTS_DIR, run_key)
    os.makedirs(artifact_dir, exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)

    logger.info("Fetching npm metadata for %s@%s", package_name, version)
    metadata, downloads, registry_url, downloads_url = _get_npm_metadata(package_name, version)
    pkg_meta = _extract_package_metadata(metadata)
    tarball_url = ((metadata.get("dist") or {}).get("tarball"))
    if not tarball_url:
        raise RuntimeError("No tarball URL found in npm metadata")

    tarball_path = os.path.join(artifact_dir, "package.tgz")
    r = requests.get(tarball_url, timeout=WORKER_TIMEOUT_SECONDS)
    r.raise_for_status()
    with open(tarball_path, "wb") as f:
        f.write(r.content)

    sha256 = _sha256_file(tarball_path)
    logger.info("Downloaded tarball %s (sha256=%s)", tarball_url, sha256)

    unpacked_dir = tempfile.mkdtemp(prefix="npm_unpack_", dir=TMP_DIR)
    with tarfile.open(tarball_path, "r:gz") as tf:
        tf.extractall(unpacked_dir)

    install_scripts = _extract_install_scripts(unpacked_dir)
    scan = _scan_files(unpacked_dir)
    verdict, score = _compute_verdict(scan["findings"], install_scripts)
    logger.info(
        "Static scan complete for %s@%s: verdict=%s score=%s files=%s findings=%s",
        package_name,
        version,
        verdict,
        score,
        scan["files_scanned"],
        len(scan["findings"]),
    )
    ai_context = {
        "package_name": package_name,
        "version": version,
        "install_scripts": install_scripts,
        "findings": scan["findings"][:200],
        "iocs": scan["iocs"],
        "downloads_last_week": downloads,
        "file_snippets": _collect_file_snippets(unpacked_dir, scan["findings"]),
    }
    package_root = os.path.join(unpacked_dir, "package")
    if not os.path.isdir(package_root):
        package_root = unpacked_dir

    report_json_path = os.path.join(report_dir, "report_full.json")
    report_md_path = os.path.join(report_dir, "report_summary.md")
    ai_md_path = os.path.join(report_dir, "report_ai_detailed.md")
    ai_json_path = os.path.join(report_dir, "report_ai_structured.json")
    manifest_path = os.path.join(report_dir, "ai_manifest.json")
    coverage_path = os.path.join(report_dir, "ai_coverage_report.json")
    batches_path = os.path.join(report_dir, "ai_batches.json")
    iocs_md_path = os.path.join(report_dir, "IOCs.md")

    manifest = _build_file_manifest(package_root)
    logger.info("Built file manifest: %s files", len(manifest))

    full_ai = None

    ai_result = run_ai_static_analysis(
        package_name,
        version,
        ai_context,
        package_root=package_root,
        report_output_path=ai_md_path,
    )
    if ai_result:
        logger.info("AI analysis completed for %s@%s using %s", package_name, version, ai_result.get("model"))
    else:
        logger.info("AI analysis skipped for %s@%s", package_name, version)

    report_json = {
        "generated_at": _now(),
        "job_id": job_id,
        "package": {
            "name": package_name,
            "version": version,
            "author": pkg_meta["author"],
            "dependencies": pkg_meta["dependencies"],
            "dependencies_count": len(pkg_meta["dependencies"]),
            "dev_dependencies": pkg_meta["dev_dependencies"],
            "dev_dependencies_count": len(pkg_meta["dev_dependencies"]),
        },
        "registry": {
            "metadata_url": registry_url,
            "downloads_url": downloads_url,
            "downloads_last_week": downloads,
            "tarball_url": tarball_url,
        },
        "tarball": {
            "url": tarball_url,
            "path": tarball_path,
            "sha256": sha256,
            "size_bytes": len(r.content),
        },
        "analysis": {
            "mode": "static_only",
            "verdict": verdict,
            "score": score,
            "files_scanned": scan["files_scanned"],
            "install_scripts": install_scripts,
            "findings": scan["findings"],
            "iocs": scan["iocs"],
            "obfuscation": scan["obfuscation"],
            "file_manifest_count": len(manifest),
            "ai": ai_result,
            "ai_full_forensics": full_ai,
        },
        "source_event": source_payload,
        "source_alert": {"summary": _source_alert_summary(source_payload)},
        "artifacts": {
            "report_full_json": report_json_path,
            "report_summary_md": report_md_path,
            "report_ai_detailed_md": ai_md_path,
            "report_ai_structured_json": ai_json_path,
            "ai_manifest_json": manifest_path,
            "iocs_md": iocs_md_path,
        },
    }

    if ai_result and ai_result.get("structured"):
        report_json["analysis"]["ai_structured_verdict"] = ai_result["structured"].get("verdict")
        report_json["analysis"]["ai_structured_confidence"] = ai_result["structured"].get("confidence")

    summary_md = "\n".join(
        [
            f"# npm Package Analysis Summary",
            f"",
            f"- Package: `{package_name}`",
            f"- Version: `{version}`",
            f"- Verdict: `{verdict}` (score: {score})",
            f"- Files scanned: {scan['files_scanned']}",
            f"- Findings: {len(scan['findings'])}",
            f"- Obfuscated files detected: {len(scan['obfuscation'])}",
            f"- Weekly downloads: {((downloads or {}).get('downloads'))}",
            f"- AI model: {((ai_result or {}).get('model')) or 'disabled'}",
            f"- AI verdict: {(((ai_result or {}).get('structured') or {}).get('verdict')) or 'n/a'}",
            f"- AI coverage: n/a (single-pass full package run)",
            f"",
            f"## Top IOCs",
            f"- URLs: {', '.join(scan['iocs']['urls'][:10]) or 'None'}",
            f"- Domains: {', '.join(scan['iocs']['domains'][:10]) or 'None'}",
            f"- IPs: {', '.join(scan['iocs']['ips'][:10]) or 'None'}",
        ]
    )

    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(report_json, f, indent=2)
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write(summary_md)

    if ai_result and ai_result.get("markdown"):
        with open(ai_md_path, "w", encoding="utf-8") as f:
            f.write(ai_result["markdown"])
    elif os.path.exists(ai_md_path):
        logger.info("AI detailed report already written by OpenCode: %s", ai_md_path)
    if ai_result and ai_result.get("structured"):
        with open(ai_json_path, "w", encoding="utf-8") as f:
            json.dump(ai_result["structured"], f, indent=2)

    ai_md_for_iocs = ""
    if os.path.exists(ai_md_path):
        try:
            with open(ai_md_path, "r", encoding="utf-8", errors="ignore") as f:
                ai_md_for_iocs = f.read()
        except Exception:
            ai_md_for_iocs = ""
    ai_iocs = _extract_iocs_from_markdown(ai_md_for_iocs)
    if not any(ai_iocs.values()):
        ai_iocs = _extract_ai_iocs(ai_result)
    _write_iocs_md(iocs_md_path, ai_iocs)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    with open(coverage_path, "w", encoding="utf-8") as f:
        json.dump({"mode": "single_pass", "note": "AI run directly on full extracted package directory"}, f, indent=2)
    with open(batches_path, "w", encoding="utf-8") as f:
        json.dump([], f, indent=2)

    logger.info("Reports saved: %s and %s", report_json_path, report_md_path)

    return report_json_path, report_md_path, report_json
