"""
Automated forensic triage engine.

Reads untriaged rows from `events`, scores each one for severity, classifies
the likely attacker intent, extracts indicators of compromise (IOCs), and
writes the result into `triage`. Designed to run as a periodic job:

    python3 -m honeypot.triage.engine --watch        # loop forever
    python3 -m honeypot.triage.engine                # single pass

Scoring is rule-based (transparent, explainable, no external service calls
needed) rather than ML-based, which keeps it auditable for a portfolio/
class writeup -- you can point at exactly why an event got its score.
"""
import argparse
import json
import re
import time
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from honeypot.common.db import get_conn, init_db

# --- IOC extraction patterns -------------------------------------------------

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
BASE64_BLOB_RE = re.compile(r"(?:[A-Za-z0-9+/]{24,}={0,2})")
SHELL_META_RE = re.compile(r"(\$\(|`|\|\||&&|;\s*rm\s|;\s*wget\s|;\s*curl\s|wget%20|curl%20|%7Csh|\|sh|\|bash)", re.IGNORECASE)
SQLI_RE = re.compile(r"(\bUNION\b.*\bSELECT\b|\bOR\s+1=1\b|--\s|';)", re.IGNORECASE)
PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f)", re.IGNORECASE)
SENSITIVE_PATH_RE = re.compile(
    r"(\.env$|wp-login\.php|phpmyadmin|\.git/config|/etc/passwd|xmlrpc\.php|"
    r"actuator/health|\.aws/credentials)",
    re.IGNORECASE,
)
KNOWN_DEFAULT_CREDS = {
    ("admin", "admin"), ("admin", "password"), ("root", "root"),
    ("root", "toor"), ("admin", "123456"), ("user", "user"),
    ("ubnt", "ubnt"), ("admin", ""),
}


def extract_iocs(text):
    if not text:
        return {}
    iocs = {}
    ips = set(IP_RE.findall(text))
    if ips:
        iocs["ips_in_payload"] = sorted(ips)
    urls = set(URL_RE.findall(text))
    if urls:
        iocs["urls"] = sorted(urls)
    b64 = [m for m in BASE64_BLOB_RE.findall(text) if len(m) >= 24]
    if b64:
        iocs["base64_blobs"] = b64[:5]
    if SHELL_META_RE.search(text):
        iocs["shell_metacharacters"] = True
    if SQLI_RE.search(text):
        iocs["sqli_pattern"] = True
    if PATH_TRAVERSAL_RE.search(text):
        iocs["path_traversal"] = True
    sensitive = SENSITIVE_PATH_RE.findall(text)
    if sensitive:
        iocs["sensitive_path_probe"] = list(set(sensitive))
    return iocs


def score_event(row, prior_events_from_ip):
    """
    Returns (score:int 0-100, severity:str, category:str, iocs:dict, rationale:str)
    """
    reasons = []
    score = 0
    category = "benign"
    payload = row["raw_payload"] or ""
    extra = json.loads(row["extra_json"] or "{}")
    full_text = " ".join([payload, json.dumps(extra)])

    iocs = extract_iocs(full_text)

    # --- baseline by event type ---
    if row["event_type"] == "connect":
        score += 2
        reasons.append("connection to decoy service (+2)")
        category = "recon"
    elif row["event_type"] == "request":
        score += 5
        reasons.append("request/banner exchange captured (+5)")
        category = "recon"
    elif row["event_type"] == "auth_attempt":
        score += 15
        reasons.append("credential submission attempt (+15)")
        category = "brute_force"
        if row["username"] and row["password"] is not None:
            pair = (row["username"], row["password"] or "")
            if pair in KNOWN_DEFAULT_CREDS:
                score += 20
                reasons.append(f"used known default credential pair {pair} (+20)")
    elif row["event_type"] == "command":
        score += 10
        reasons.append("post-connect command/data sent (+10)")

    # --- payload-based escalation ---
    if iocs.get("shell_metacharacters"):
        score += 30
        category = "exploit_attempt"
        reasons.append("shell metacharacters / command-injection pattern detected (+30)")
    if iocs.get("sqli_pattern"):
        score += 30
        category = "exploit_attempt"
        reasons.append("SQL injection pattern detected (+30)")
    if iocs.get("path_traversal"):
        score += 20
        category = "exploit_attempt"
        reasons.append("path traversal sequence detected (+20)")
    if iocs.get("sensitive_path_probe"):
        score += 15
        category = "recon" if category == "benign" else category
        reasons.append(f"probed sensitive path(s): {iocs['sensitive_path_probe']} (+15)")
    if iocs.get("urls") or iocs.get("base64_blobs"):
        score += 25
        category = "malware_drop"
        reasons.append("payload contains URL(s) and/or base64 blob, possible stager/dropper (+25)")

    # --- behavioral escalation: repeat offenders from same IP ---
    if prior_events_from_ip >= 20:
        score += 15
        reasons.append(f"high-volume source IP, {prior_events_from_ip} prior events (+15)")
    elif prior_events_from_ip >= 5:
        score += 8
        reasons.append(f"repeat source IP, {prior_events_from_ip} prior events (+8)")

    score = min(score, 100)
    if score >= 80:
        severity = "critical"
    elif score >= 55:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    elif score >= 10:
        severity = "low"
    else:
        severity = "info"

    return score, severity, category, iocs, "; ".join(reasons)


def run_triage_pass():
    init_db()
    conn = get_conn()
    untriaged = conn.execute(
        """SELECT e.* FROM events e
           LEFT JOIN triage t ON e.id = t.event_id
           WHERE t.event_id IS NULL
           ORDER BY e.id ASC"""
    ).fetchall()

    if not untriaged:
        conn.close()
        return 0

    # build a running count of prior events per IP for behavioral scoring
    ip_counts = defaultdict(int)
    all_counts = conn.execute(
        "SELECT src_ip, COUNT(*) c FROM events GROUP BY src_ip"
    ).fetchall()
    for r in all_counts:
        ip_counts[r["src_ip"]] = r["c"]

    for row in untriaged:
        score, severity, category, iocs, rationale = score_event(row, ip_counts[row["src_ip"]])
        conn.execute(
            """INSERT INTO triage (event_id, severity, score, category, iocs_json, rationale, triaged_at)
               VALUES (?,?,?,?,?,?,?)""",
            (row["id"], severity, score, category, json.dumps(iocs), rationale, time.time()),
        )

    # refresh ip_reputation rollup table
    conn.execute("DELETE FROM ip_reputation")
    rollup = conn.execute(
        """
        SELECT e.src_ip,
               MIN(e.ts) first_seen, MAX(e.ts) last_seen,
               COUNT(*) total_events,
               COALESCE(MAX(t.score), 0) max_severity_score,
               COUNT(DISTINCT e.service) distinct_services
        FROM events e LEFT JOIN triage t ON e.id = t.event_id
        GROUP BY e.src_ip
        """
    ).fetchall()
    for r in rollup:
        is_bad = 1 if (r["max_severity_score"] >= 55 or r["total_events"] >= 20) else 0
        conn.execute(
            """INSERT INTO ip_reputation
               (src_ip, first_seen, last_seen, total_events, max_severity_score, distinct_services, is_known_bad)
               VALUES (?,?,?,?,?,?,?)""",
            (r["src_ip"], r["first_seen"], r["last_seen"], r["total_events"],
             r["max_severity_score"], r["distinct_services"], is_bad),
        )

    conn.commit()
    n = len(untriaged)
    conn.close()
    return n


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--watch", action="store_true", help="run continuously")
    p.add_argument("--interval", type=int, default=5, help="seconds between passes when --watch")
    args = p.parse_args()

    if args.watch:
        print("[triage] watching for new events... (Ctrl+C to stop)")
        while True:
            n = run_triage_pass()
            if n:
                print(f"[triage] processed {n} new event(s)")
            time.sleep(args.interval)
    else:
        n = run_triage_pass()
        print(f"[triage] processed {n} event(s)")


if __name__ == "__main__":
    main()
