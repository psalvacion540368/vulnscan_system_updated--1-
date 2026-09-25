# VulnAssess — Automated Vulnerability Scanning and Risk Assessment System

A Django-based system implementing the five modules from the project proposal:

1. **`accounts/`** — Authentication & Role-Based Access Control
   Custom `User` model with `ADMIN` / `ANALYST` / `VIEWER` roles, PBKDF2 (default)
   or BCrypt password hashing, a `role_required(...)` decorator for view-level
   authorization, and a full audit trail (`AuditLogEntry`) of logins, role
   changes, scans, and denied-access attempts.

2. **`scanning/`** — Network Scanning & Packet Execution Engine
   `scanning/engine.py` parses **IPs, CIDR ranges, and web hostnames/domains**
   (with or without `http(s)://`, a path, or a `:port`) from a single input
   field, enforces **separate authorization allow-lists** for each
   (`SCAN_ALLOWED_CIDRS` for IP/CIDR targets, `SCAN_ALLOWED_DOMAINS` for web
   targets) before any packet is sent, runs lightweight Scapy-based discovery
   (ARP sweep / ICMP / SYN-ACK probes), and wraps Nmap via `python-nmap` for
   port, service-version, OS fingerprinting, and web-service checks.

3. **`vulnassess/`** — Vulnerability Assessment & Correlation Engine
   `vulnassess/matcher.py` correlates discovered service/version signatures
   against a local `CVERecord` table (seeded from `vulnassess/data/cve_local_db.json`),
   evaluates a small built-in set of configuration-flaw checks (Telnet/FTP/VNC/SMB
   exposure), computes a 0–10 composite risk score, and assigns
   Critical/High/Medium/Low severity with predefined remediation text.
   `vulnassess/comparison.py` diffs findings between two scans of the same
   target (new / resolved / unchanged) and tracks severity counts over time.

4. **Data Persistence Layer** — Django ORM across all four apps, backed by
   **MySQL** (`vulnscan/settings.py`), with an optional SQLite fallback for
   quick local evaluation via `VULNSCAN_USE_SQLITE=True`.

5. **`reporting/`** — Presentation & Reporting Engine
   A role-aware dashboard (severity breakdown, overall risk rating, top
   findings, mitigation guide) plus PDF (`reportlab`) and CSV export of any
   completed scan's findings, downloadable from the Reports page. An
   **Analytics** page (`/analytics/`) adds Chart.js visualizations on top of
   the same data: severity distribution, a findings-over-time trend line
   (7/30/90-day toggle), scan-job outcome breakdown, the top 5 riskiest hosts
   by finding count, and a most-frequent-CVEs table — all read-only for every
   role, same visibility as the dashboard.

## Multi-target scanning

A single **Target** can be any of the following — the system auto-detects
which kind it is and applies the matching authorization check:

| Target format | Example | Authorization check |
|---|---|---|
| Single IP | `192.168.1.10` | `SCAN_ALLOWED_CIDRS` |
| CIDR range | `192.168.1.0/24` | `SCAN_ALLOWED_CIDRS` |
| Web hostname/domain | `example.com` | `SCAN_ALLOWED_DOMAINS` |
| Full URL (scheme/path stripped automatically) | `https://example.com/page` | `SCAN_ALLOWED_DOMAINS` |
| Host with port (port stripped automatically) | `localhost:5225` | always allowed (own machine) |
| `localhost` | `localhost` | always allowed (own machine) |

Scan types available per target:
- **Host discovery** — Scapy ARP/ICMP/SYN sweep (IP/CIDR targets only)
- **Port & service scan** — Nmap `-sV` version detection
- **Full scan** — adds `-O` OS fingerprinting
- **Web scan** — Nmap `--script=http-title,http-headers,http-enum` against common web ports

## Setup with XAMPP (MySQL)

1. **Start MySQL** in the XAMPP Control Panel.
2. **Create the database and app user** — open `http://localhost/phpmyadmin`,
   go to the **SQL** tab, and run:
   ```sql
   CREATE DATABASE vulnscan_db CHARACTER SET utf8mb4;
   CREATE USER 'vulnscan_app'@'localhost' IDENTIFIED BY 'YourPassword123!';
   GRANT ALL PRIVILEGES ON vulnscan_db.* TO 'vulnscan_app'@'localhost';
   FLUSH PRIVILEGES;
   ```
3. **Install dependencies:**
   ```bash
   py -m pip install -r requirements.txt
   ```
   `mysqlclient` is the preferred driver; if it fails to build on Windows,
   `pip install pymysql` also works — `settings.py` auto-detects whichever
   one is installed, no manual code changes needed.
4. **Configure `.env`** (copy from `.env.example`):
   ```
   VULNSCAN_USE_SQLITE=False
   DB_NAME=vulnscan_db
   DB_USER=vulnscan_app
   DB_PASSWORD=YourPassword123!
   DB_HOST=127.0.0.1
   DB_PORT=3306
   SCAN_ALLOWED_CIDRS=10.0.0.0/8,192.168.0.0/16
   SCAN_ALLOWED_DOMAINS=scanme.nmap.org
   ```
5. **Run migrations and seed data:**
   ```bash
   py manage.py makemigrations accounts scanning vulnassess reporting
   py manage.py migrate
   py manage.py load_cve_database
   py manage.py bootstrap_admin --username admin --email admin@example.com --password "ChangeMe!123"
   ```
6. **Start the server:**
   ```bash
   py manage.py runserver
   ```
   Visit `http://127.0.0.1:8000/accounts/login/`.

## Quick start without MySQL (SQLite fallback)

Set `VULNSCAN_USE_SQLITE=True` in `.env` and skip the XAMPP/MySQL steps —
everything else (migrations, seeding, running the server) is identical.
Useful for quick local testing before your MySQL setup is ready.

## Important operational notes

- **`DJANGO_HTTPS` must match how you're actually serving the site.** Leave
  it `False` for local development over plain `http://127.0.0.1:8000`
  (the default in `.env`) — `True` marks the session/CSRF cookies
  `Secure`, so browsers/clients silently refuse to send them back over
  plain HTTP and every form POST (login included) fails with a 403 CSRF
  error. Only set it `True` once the app is actually served over HTTPS.

- **Authorization scope is enforced twice, separately.** IP/CIDR targets
  check `SCAN_ALLOWED_CIDRS` (defaults to RFC1918 private ranges + loopback
  if left blank); hostname/domain targets check `SCAN_ALLOWED_DOMAINS`
  (deny-all by default — you must explicitly list domains you're authorized
  to test). `localhost` is always allowed since it can only ever refer to
  the machine running the scan. **Never add a domain you don't own or have
  written authorization to test** — this allow-list exists specifically to
  prevent scanning systems you don't control.
- **Raw sockets.** Scapy probing and Nmap's `-O` OS-fingerprinting flag need
  raw-socket privileges (run as Administrator on Windows) and Npcap
  installed (bundled with the Nmap Windows installer). Without these,
  drop `-O` from the scan arguments and use Port scan instead of Full scan.
- **Background execution.** Scans run in a background thread per request
  (`scanning/views.py:_run_job_safely`). For production load, swap this for
  a proper task queue (Celery + Redis/RabbitMQ).
- **CVE data freshness.** `cve_local_db.json` is a small illustrative sample
  (10 well-known CVEs), not a full NVD mirror. `settings.NVD_API_BASE` /
  `NVD_API_KEY` are wired up for building a scheduled sync command later.
- **Report files.** Generated PDFs/CSVs are written under `media/reports/`.
- **Timezone.** `TIME_ZONE = "Asia/Manila"` — all timestamps (audit logs,
  scan queued/finished times, report dates) display in Philippine time.

## Project layout

```
vulnscan_system/
├── manage.py
├── requirements.txt
├── .env.example
├── vulnscan/            # project settings, root urls
├── accounts/            # Module 1: Auth & RBAC
├── scanning/            # Module 2: Scanning & packet execution (IP/CIDR/web)
├── vulnassess/          # Module 3: Vulnerability correlation + comparison
├── reporting/           # Module 5: Dashboard & report generation
├── templates/base.html  # shared role-aware nav/layout
└── static/css/main.css  # HTML5/CSS3 presentation layer
```

## Default role permissions

| Capability                          | Admin | Analyst | Viewer |
|--------------------------------------|:---:|:---:|:---:|
| View dashboard / risk ratings        | ✅ | ✅ | ✅ |
| View & download reports              | ✅ | ✅ | ✅ |
| Launch scans (IP/CIDR/web)           | ✅ | ✅ | ❌ |
| Analyze vulnerabilities / findings   | ✅ | ✅ | ❌ |
| Compare scans / view trends          | ✅ | ✅ | ❌ |
| Generate reports                     | ✅ | ✅ | ❌ |
| Manage accounts / roles              | ✅ | ❌ | ❌ |
| View system-wide audit logs          | ✅ | ❌ | ❌ |
| Configure scanning allow-list        | ✅ | ❌ | ❌ |
