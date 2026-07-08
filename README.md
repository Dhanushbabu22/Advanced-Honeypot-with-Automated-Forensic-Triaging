# Sentinel — Multi-Service Honeypot with Automated Forensic Triage

A defensive security lab project: three lightweight decoy services (SSH, HTTP,
FTP) that capture attacker interaction, an automated rule-based triage engine
that scores and classifies each event, and a web dashboard for reviewing
results in real time.

## Architecture

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  ssh_decoy   │  │  http_decoy  │  │  ftp_decoy   │   <- decoy services
│  (port 2222) │  │  (port 8080) │  │  (port 2121) │      (services/)
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                          ▼
                  honeypot.db (SQLite)            <- common/db.py
                  table: events
                          │
                          ▼
              triage.engine (rule-based scorer)    <- triage/engine.py
              writes: table triage, ip_reputation
                          │
                          ▼
              dashboard.app (Flask + REST API)     <- dashboard/
              http://localhost:5000
```

Each decoy speaks just enough of its protocol's handshake (a real-looking
banner, a login prompt) to get scanners and bots to send credentials or
payloads. None of them implement real authentication, a real shell, or real
file access — every connection is logged and then dropped or rejected.

The triage engine is intentionally **rule-based, not ML-based**, so every
score is explainable: each event's `rationale` field states exactly which
heuristics fired and why (e.g. "used known default credential pair
('admin','admin') (+20); shell metacharacters detected (+30)"). This is the
kind of explainability you want in a portfolio write-up or a SOC tool — an
analyst can audit *why* something was flagged.

### What the triage engine looks for

- **Credential analysis** — matches against a known default-credential list,
  flags repeated auth attempts from the same source.
- **Payload analysis** — regex-based detection of shell metacharacters,
  SQL injection patterns, path traversal sequences, probes of sensitive
  paths (`.env`, `.git/config`, `wp-login.php`, etc.), and embedded
  URLs/base64 blobs that suggest a malware stager/dropper.
- **Behavioral scoring** — escalates severity for source IPs with a high
  volume of repeat connections across services.
- **IOC extraction** — pulls out IPs, URLs, and base64 blobs found in
  payloads for later correlation with threat intel feeds.

Severity buckets: `info` (0-9) → `low` (10-29) → `medium` (30-54) →
`high` (55-79) → `critical` (80-100).

## Running it

Requires Python 3.10+ and `flask` (`pip install flask --break-system-packages`
if you hit an externally-managed-environment error).

```bash
cd honeypot
export PYTHONPATH=$(pwd)/..

# Terminal 1-3: start decoys (use high, non-privileged ports for local testing)
python3 -m honeypot.services.ssh_decoy  --port 2222
python3 -m honeypot.services.http_decoy --port 8080
python3 -m honeypot.services.ftp_decoy  --port 2121

# Terminal 4: continuously triage new events
python3 -m honeypot.triage.engine --watch

# Terminal 5: dashboard
python3 -m honeypot.dashboard.app --port 5000
```

Open `http://localhost:5000`. Generate test traffic against your own
instance with `curl`, `nc`, or an `ftp`/`ssh` client pointed at the decoy
ports — the dashboard updates every 5 seconds.

Quick manual test:
```bash
curl -X POST http://localhost:8080/wp-login.php -d "username=admin&password=admin"
printf 'USER root\r\nPASS toor\r\n' | nc localhost 2121
```

## Ethical & legal considerations (worth including in your write-up)

- **Run this only in a lab/VM you control**, not exposed directly to the
  internet on a host you don't own outright. Operating an internet-facing
  honeypot that captures third-party traffic raises jurisdiction-specific
  legal questions (wiretap/interception statutes, data retention rules) —
  research the law in your jurisdiction before deploying beyond a local lab.
- The decoys never execute, forward, or act on anything they receive — they
  only log it. This avoids the honeypot itself becoming an attack vector.
- If you do eventually deploy this on an isolated, properly-authorized lab
  network, scrub IPs / credentials before sharing captured data publicly —
  some of it will belong to real third parties (scanning bots, researchers,
  etc.) even though no real harm occurred.

## Possible extensions for the writeup

- Swap the rule-based scorer for an ML classifier and compare explainability
  tradeoffs.
- Add a `telnet` or `redis` decoy.
- Enrich IOCs with a local GeoIP database or threat-intel feed lookup.
- Add alerting (webhook/email) when an event crosses the `critical` threshold.
