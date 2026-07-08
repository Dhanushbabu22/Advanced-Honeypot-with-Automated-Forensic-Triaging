"""
Web dashboard for viewing honeypot activity and triage results.

Run as: python3 -m honeypot.dashboard.app --port 5000
Then open http://localhost:5000
"""
import argparse
import json
import sys
from pathlib import Path
from flask import Flask, jsonify, render_template

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from honeypot.common.db import get_conn, init_db

app = Flask(__name__, template_folder="templates")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    conn = get_conn()
    total_events = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    total_ips = conn.execute("SELECT COUNT(DISTINCT src_ip) c FROM events").fetchone()["c"]
    by_severity = conn.execute(
        "SELECT severity, COUNT(*) c FROM triage GROUP BY severity"
    ).fetchall()
    by_service = conn.execute(
        "SELECT service, COUNT(*) c FROM events GROUP BY service"
    ).fetchall()
    by_category = conn.execute(
        "SELECT category, COUNT(*) c FROM triage GROUP BY category"
    ).fetchall()
    conn.close()
    return jsonify({
        "total_events": total_events,
        "total_ips": total_ips,
        "by_severity": {r["severity"]: r["c"] for r in by_severity},
        "by_service": {r["service"]: r["c"] for r in by_service},
        "by_category": {r["category"]: r["c"] for r in by_category},
    })


@app.route("/api/events")
def api_events():
    conn = get_conn()
    rows = conn.execute(
        """SELECT e.id, e.ts, e.service, e.src_ip, e.src_port, e.event_type,
                  e.username, e.password, e.raw_payload,
                  t.severity, t.score, t.category, t.iocs_json, t.rationale
           FROM events e
           LEFT JOIN triage t ON e.id = t.event_id
           ORDER BY e.id DESC
           LIMIT 200"""
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["iocs"] = json.loads(d.pop("iocs_json")) if d.get("iocs_json") else {}
        out.append(d)
    return jsonify(out)


@app.route("/api/top_offenders")
def api_top_offenders():
    conn = get_conn()
    rows = conn.execute(
        """SELECT * FROM ip_reputation
           ORDER BY max_severity_score DESC, total_events DESC
           LIMIT 25"""
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
@app.route("/api/analyze")
def api_analyze():
    from flask import request as freq
    ip_filter = freq.args.get("ip", None)
    conn = get_conn()
    if ip_filter:
        events = conn.execute(
            """SELECT e.*, t.severity, t.score, t.category, t.rationale, t.iocs_json
               FROM events e LEFT JOIN triage t ON e.id = t.event_id
               WHERE e.src_ip = ?
               ORDER BY e.ts DESC LIMIT 100""", (ip_filter,)
        ).fetchall()
    else:
        events = conn.execute(
            """SELECT e.*, t.severity, t.score, t.category, t.rationale, t.iocs_json
               FROM events e LEFT JOIN triage t ON e.id = t.event_id
               ORDER BY e.ts DESC LIMIT 100"""
        ).fetchall()
    ips = conn.execute("SELECT * FROM ip_reputation ORDER BY max_severity_score DESC").fetchall()
    conn.close()

    total = len(events)
    if total == 0:
        return jsonify({"report": "No events to analyze yet."})

    # Count categories
    cats = {}
    sevs = {}
    services = {}
    creds = []
    iocs = []
    for e in events:
        c = e["category"] or "unknown"
        s = e["severity"] or "info"
        svc = e["service"]
        cats[c] = cats.get(c,0) + 1
        sevs[s] = sevs.get(s,0) + 1
        services[svc] = services.get(svc,0) + 1
        if e["username"]:
            creds.append(f"{e['username']}/{e['password']}")
        try:
            ioc = json.loads(e["iocs_json"] or "{}")
            if ioc: iocs.append(ioc)
        except: pass

    critical = sevs.get("critical",0)
    high = sevs.get("high",0)
    medium = sevs.get("medium",0)
    low = sevs.get("low",0)
    info = sevs.get("info",0)

    # Threat level
    if critical > 0:
        threat_level = "CRITICAL"
        threat_color = "red"
    elif high > 0:
        threat_level = "HIGH"
        threat_color = "orange"
    elif medium > 0:
        threat_level = "MEDIUM"
        threat_color = "yellow"
    else:
        threat_level = "LOW"
        threat_color = "green"

    # MITRE ATT&CK mapping
    mitre = []
    if cats.get("brute_force",0) > 0:
        mitre.append({"id":"T1110","name":"Brute Force","tactic":"Credential Access"})
    if cats.get("recon",0) > 0:
        mitre.append({"id":"T1595","name":"Active Scanning","tactic":"Reconnaissance"})
    if cats.get("exploit_attempt",0) > 0:
        mitre.append({"id":"T1190","name":"Exploit Public-Facing Application","tactic":"Initial Access"})
    if cats.get("malware_drop",0) > 0:
        mitre.append({"id":"T1059","name":"Command and Scripting Interpreter","tactic":"Execution"})

    # Top attacker IPs
    top_ips = [dict(ip) for ip in ips[:5]]

    # Unique credentials
    unique_creds = list(set(creds))[:10]

    # Recommendations
    recommendations = []
    if cats.get("brute_force",0) > 0:
        recommendations.append("Block IPs with more than 3 failed login attempts using fail2ban")
    if cats.get("recon",0) > 0:
        recommendations.append("Hide sensitive files (.env, .git) using web server rules")
    if cats.get("exploit_attempt",0) > 0:
        recommendations.append("Deploy a Web Application Firewall (WAF) to block SQLi/XSS")
    if cats.get("malware_drop",0) > 0:
        recommendations.append("Block outbound connections to unknown IPs using firewall rules")
    if services.get("ssh",0) > 0:
        recommendations.append("Disable password auth on SSH — use key-based authentication only")
    if services.get("ftp",0) > 0:
        recommendations.append("Disable FTP — use SFTP instead for secure file transfer")

    report = {
        "threat_level": threat_level,
        "threat_color": threat_color,
        "total_events": total,
        "summary": {
            "by_severity": sevs,
            "by_category": cats,
            "by_service": services,
        },
        "mitre_attack": mitre,
        "top_ips": top_ips,
        "credentials_captured": unique_creds,
        "recommendations": recommendations,
        "ioc_count": len(iocs),
    }
    return jsonify(report)


@app.route("/api/analyze/<int:event_id>")
def api_analyze_event(event_id):
    conn = get_conn()
    row = conn.execute(
        """SELECT e.*, t.severity, t.score, t.category, t.rationale, t.iocs_json
           FROM events e LEFT JOIN triage t ON e.id = t.event_id
           WHERE e.id = ?""", (event_id,)
    ).fetchone()
    ip_rep = conn.execute(
        "SELECT * FROM ip_reputation WHERE src_ip = ?", (row["src_ip"],)
    ).fetchone() if row else None
    conn.close()

    if not row:
        return jsonify({"error": "Event not found"})

    e = dict(row)
    ip = dict(ip_rep) if ip_rep else {}

    # IOC analysis
    try:
        iocs = json.loads(e.get("iocs_json") or "{}")
    except:
        iocs = {}

    # Technique mapping
    techniques = []
    cat = e.get("category","")
    if cat == "brute_force":
        techniques.append({"id":"T1110","name":"Brute Force","tactic":"Credential Access","detail":"Attacker submitted credentials to gain unauthorized access"})
    if cat == "recon":
        techniques.append({"id":"T1595","name":"Active Scanning","tactic":"Reconnaissance","detail":"Attacker probed the system to discover attack surface"})
    if cat == "exploit_attempt":
        techniques.append({"id":"T1190","name":"Exploit Public-Facing Application","tactic":"Initial Access","detail":"Attacker attempted to exploit a vulnerability in the application"})
    if cat == "malware_drop":
        techniques.append({"id":"T1059","name":"Command and Scripting Interpreter","tactic":"Execution","detail":"Attacker tried to download and execute malicious code"})

    # Risk assessment
    score = e.get("score") or 0
    if score >= 80:
        risk = "CRITICAL"; risk_detail = "Immediate action required — active exploitation attempt detected"
    elif score >= 55:
        risk = "HIGH"; risk_detail = "High priority — attacker showing aggressive behavior"
    elif score >= 30:
        risk = "MEDIUM"; risk_detail = "Monitor closely — suspicious activity detected"
    elif score >= 10:
        risk = "LOW"; risk_detail = "Low priority — basic probe or scan"
    else:
        risk = "INFO"; risk_detail = "Informational — normal background noise"

    # Attacker profile
    profile = []
    if e.get("username"):
        profile.append(f"Used credential pair: {e.get('username')}/{e.get('password')}")
    if iocs.get("sqli_pattern"):
        profile.append("Attempted SQL injection attack")
    if iocs.get("shell_metacharacters"):
        profile.append("Attempted command injection attack")
    if iocs.get("path_traversal"):
        profile.append("Attempted path traversal attack")
    if iocs.get("sensitive_path_probe"):
        profile.append(f"Probed sensitive paths: {iocs['sensitive_path_probe']}")
    if iocs.get("urls"):
        profile.append(f"Payload contained URLs: {iocs['urls']}")
    if iocs.get("base64_blobs"):
        profile.append("Payload contained base64 encoded data — possible malware stager")
    if ip.get("total_events",0) >= 5:
        profile.append(f"Repeat offender — {ip.get('total_events')} total events from this IP")

    # Recommended actions
    actions = []
    if score >= 55:
        actions.append(f"Block IP {e['src_ip']} immediately in firewall")
    if cat == "brute_force":
        actions.append("Add to fail2ban blocklist")
        actions.append("Enable account lockout after 3 failed attempts")
    if cat == "exploit_attempt":
        actions.append("Review and patch the targeted vulnerability")
        actions.append("Deploy WAF rule to block this attack pattern")
    if cat == "malware_drop":
        actions.append("Block outbound connections to detected URLs")
        actions.append("Scan system for any successful compromise")
    if cat == "recon":
        actions.append("Hide sensitive files from public access")
        actions.append("Review server configuration and remove exposed endpoints")

    return jsonify({
        "event_id": event_id,
        "risk_level": risk,
        "risk_detail": risk_detail,
        "score": score,
        "severity": e.get("severity","info"),
        "category": cat,
        "src_ip": e.get("src_ip"),
        "service": e.get("service"),
        "event_type": e.get("event_type"),
        "attacker_profile": profile,
        "techniques": techniques,
        "iocs": iocs,
        "recommended_actions": actions,
        "ip_reputation": ip,
    })


if __name__ == "__main__":
    init_db()
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    args = p.parse_args()
    app.run(host=args.host, port=args.port, debug=False)
