"""
Network Scanning & Packet Execution Engine.

Responsibilities (per spec):
  * IP Parsing            -> parse_targets()
  * Network Discovery     -> discover_hosts()   (Scapy ARP/ICMP + SYN probes)
  * Port & Version ID     -> run_nmap_scan()    (python-nmap wrapper around Nmap)

Design notes:
  - Every entry point re-validates that the requested target is inside
    settings.SCAN_ALLOWED_CIDRS before a single packet is sent. This is a
    hard authorization guardrail, independent of RBAC, so a compromised or
    misconfigured account still cannot scan networks the deployment wasn't
    explicitly authorized to test.
  - Raw packet crafting (Scapy) is used only for lightweight, low-noise
    discovery/liveness probing. Deep service enumeration is delegated to
    Nmap itself via python-nmap, which is the well-tested, rate-limited way
    to do version detection instead of hand-rolling probes.
"""
import ipaddress
import logging
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

audit_logger = logging.getLogger("vulnscan.audit")

# Basic hostname/domain syntax check (e.g. "example.com", "sub.example.co.uk").
# Deliberately conservative -- anything that doesn't look like a clean domain
# falls through to the ValueError in parse_targets rather than being guessed at.
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class UnauthorizedTargetError(Exception):
    """Raised when a requested target falls outside the configured allow-list."""


class ScanExecutionError(Exception):
    """Raised when Nmap/Scapy execution fails."""


# ---------------------------------------------------------------------------
# IP Parsing (also accepts web hostnames/domains alongside IPs and CIDRs)
# ---------------------------------------------------------------------------
def parse_targets(raw_input: str):
    """
    Accepts a single IP, a CIDR range, a hostname/domain (e.g. example.com or
    a subdomain), the special hostname "localhost", or a comma-separated mix
    of these -- with or without a "http(s)://", trailing path, or ":port".
    Returns a list where each item is either an ipaddress object (IP/CIDR),
    the string "localhost", or a plain hostname/domain string. Raises
    ValueError on malformed input.
    """
    targets = []
    for chunk in (c.strip() for c in raw_input.split(",")):
        if not chunk:
            continue
        # Strip a leading scheme and trailing path, e.g.
        # "https://example.com/path?x=1" -> "example.com"
        cleaned = re.sub(r"^https?://", "", chunk).split("/")[0].split("?")[0].strip()
        # Strip a trailing ":port" (but leave bracketed/plain IPv6 addresses,
        # which contain multiple colons, alone).
        if cleaned.count(":") == 1:
            host_part, _, port_part = cleaned.partition(":")
            if port_part.isdigit():
                cleaned = host_part

        is_cidr = "/" in chunk and not chunk.lower().startswith(("http://", "https://"))
        try:
            if is_cidr:
                targets.append(ipaddress.ip_network(chunk, strict=False))
                continue
            targets.append(ipaddress.ip_address(cleaned))
            continue
        except ValueError:
            pass

        if cleaned.lower() == "localhost":
            targets.append("localhost")
        elif _HOSTNAME_RE.match(cleaned):
            targets.append(cleaned.lower())
        else:
            raise ValueError(f"'{chunk}' is not a valid IP address, CIDR range, or hostname")

    if not targets:
        raise ValueError("No targets supplied")
    return targets


def _domain_authorized(hostname: str) -> bool:
    """
    Web targets are authorized against settings.SCAN_ALLOWED_DOMAINS -- a
    separate, explicit allow-list from the IP/CIDR one, since a domain
    resolving outside your own network is a different authorization
    question than scanning a private subnet. Deny by default: an empty
    list means no web targets are authorized yet. "localhost" is always
    authorized -- it can only ever refer to the machine running the scan.
    """
    if hostname.lower() == "localhost":
        return True
    allowed_domains = [d.strip().lower() for d in settings.SCAN_ALLOWED_DOMAINS if d.strip()]
    hostname = hostname.lower()
    return any(hostname == d or hostname.endswith("." + d) for d in allowed_domains)


def assert_authorized(raw_input: str):
    """
    Enforces the authorization allow-lists. IP/CIDR targets are checked
    against SCAN_ALLOWED_CIDRS (defaulting to RFC1918 + loopback if that's
    empty); hostname/domain targets are checked against the separate
    SCAN_ALLOWED_DOMAINS list, which is empty (deny-all) by default.
    """
    parsed = parse_targets(raw_input)
    allowed_networks = [ipaddress.ip_network(c.strip(), strict=False) for c in settings.SCAN_ALLOWED_CIDRS if c.strip()]
    if not allowed_networks:
        allowed_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]

    for t in parsed:
        if isinstance(t, str):
            if not _domain_authorized(t):
                raise UnauthorizedTargetError(
                    f"{t} is not in this deployment's authorized web-scanning scope "
                    f"(add it to SCAN_ALLOWED_DOMAINS)."
                )
            continue
        network = t if isinstance(t, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else ipaddress.ip_network(t)
        if not any(network.subnet_of(allowed) for allowed in allowed_networks):
            raise UnauthorizedTargetError(
                f"{t} is outside the authorized scanning scope for this deployment."
            )
    return parsed


def is_web_target(raw_input: str) -> bool:
    """True if any target in raw_input is a hostname/domain rather than an IP/CIDR."""
    return any(isinstance(t, str) for t in parse_targets(raw_input))


def discover_managed_wifi_targets():
    """Return the connected Windows Wi-Fi SSID and its local IPv4/CIDR."""
    if sys.platform != "win32":
        return []
    try:
        wlan = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
        ipconfig = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    name_match = re.search(r"^\s*Name\s*:\s*(.+)$", wlan, re.MULTILINE | re.IGNORECASE)
    ssid_match = re.search(r"^\s*SSID\s*:\s*(.+)$", wlan, re.MULTILINE | re.IGNORECASE)
    interface_name = name_match.group(1).strip() if name_match else ""
    ssid = ssid_match.group(1).strip() if ssid_match else ""
    if not ssid or re.search(r"^\s*State\s*:\s*connected\s*$", wlan, re.MULTILINE | re.IGNORECASE) is None:
        return []
    adapter_block = re.search(
        rf"(?im)^.*adapter\s+{re.escape(interface_name)}\s*:\s*(.*?)(?=^\S.*adapter\s+|\Z)",
        ipconfig, re.DOTALL,
    )
    adapter_text = adapter_block.group(1) if adapter_block else ipconfig
    ipv4_match = re.search(
        r"IPv4 Address[^:]*:\s*([0-9.]+).*?Subnet Mask[^:]*:\s*([0-9.]+)",
        adapter_text, re.DOTALL | re.IGNORECASE,
    )
    if not ipv4_match:
        return []
    try:
        address = ipaddress.ip_interface(f"{ipv4_match.group(1)}/{ipv4_match.group(2)}")
    except ValueError:
        return []
    return [{"ssid": ssid, "ip_address": str(address.ip), "cidr": str(address.network)}]


def calculate_attacker_risk(job):
    """Calculate an explainable 0-100 attacker-risk triage score."""
    from .models import SecurityTransaction

    score = 0
    reasons = []
    recent = SecurityTransaction.objects.filter(
        created_at__gte=timezone.now() - timedelta(minutes=15),
    )
    denied = recent.filter(status__in=[SecurityTransaction.Status.DECLINED, SecurityTransaction.Status.BLOCKED])
    if denied.exists():
        score += 35
        reasons.append(f"{denied.count()} denied or blocked transaction(s) in the last 15 minutes")
    burst_count = recent.count()
    if burst_count >= 5:
        score += 20
        reasons.append(f"High transaction burst: {burst_count} events in the last 15 minutes")
    scanned_ips = list(job.hosts.values_list("ip_address", flat=True))
    if recent.filter(source_ip__in=scanned_ips).exists():
        score += 25
        reasons.append("A scanned host initiated a recent security transaction")
    suspicious_ports = job.hosts.filter(
        ports__port_number__in=[21, 23, 445, 3389, 5900]
    ).distinct().count()
    if suspicious_ports:
        score += min(20, suspicious_ports * 5)
        reasons.append(f"{suspicious_ports} host(s) expose commonly abused remote-access ports")
    score = min(score, 100)
    label = "HIGH" if score >= 70 else "MEDIUM" if score >= 35 else "LOW"
    return score, label, reasons


# ---------------------------------------------------------------------------
# Network Discovery (Scapy)
# ---------------------------------------------------------------------------
@dataclass
class ProbeResult:
    ip_address: str
    is_up: bool
    mac_address: str = ""
    notes: str = ""


def discover_hosts(cidr: str, timeout: float = 2.0):
    """
    Lightweight liveness sweep using Scapy: ARP for local subnets, an ICMP
    echo + a single TCP SYN-to-443 fallback probe for routed targets. This
    keeps discovery fast and low-noise before handing surviving hosts to
    Nmap for the heavier version-detection pass.
    """
    try:
        from scapy.all import ARP, Ether, IP, ICMP, TCP, srp, sr1, conf
    except ImportError as exc:
        raise ScanExecutionError(
            "Scapy is not installed in this environment. Install with `pip install scapy` "
            "and ensure the process has raw-socket capabilities (CAP_NET_RAW / run as root)."
        ) from exc

    conf.verb = 0
    network = ipaddress.ip_network(cidr, strict=False)
    results = []

    if network.is_private and network.prefixlen >= 16:
        # ARP sweep -- fast and reliable on local L2 segments.
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = srp(pkt, timeout=timeout, retry=1)
        seen = set()
        for _, resp in answered:
            seen.add(resp.psrc)
            results.append(ProbeResult(ip_address=resp.psrc, is_up=True, mac_address=resp.hwsrc, notes="ARP reply"))
        return results

    # Routed / larger range: ICMP echo, then SYN/ACK probe on 443 as a fallback
    # for hosts that filter ICMP (common in hardened environments).
    for host in network.hosts():
        ip_str = str(host)
        icmp_resp = sr1(IP(dst=ip_str) / ICMP(), timeout=timeout, verbose=0)
        if icmp_resp is not None:
            results.append(ProbeResult(ip_address=ip_str, is_up=True, notes="ICMP echo reply"))
            continue

        syn_resp = sr1(IP(dst=ip_str) / TCP(dport=443, flags="S"), timeout=timeout, verbose=0)
        if syn_resp is not None and syn_resp.haslayer(TCP) and syn_resp[TCP].flags in (0x12, "SA"):
            results.append(ProbeResult(ip_address=ip_str, is_up=True, notes="TCP SYN/ACK on 443 (ICMP filtered)"))

    return results


# ---------------------------------------------------------------------------
# Port & Version Identification (python-nmap wrapper)
# ---------------------------------------------------------------------------
@dataclass
class NmapHostResult:
    ip_address: str
    hostname: str = ""
    state: str = "up"
    os_family: str = ""
    os_accuracy: int = None
    ports: list = field(default_factory=list)  # list of dicts: port, proto, service, product, version, extrainfo


def run_nmap_scan(target: str, arguments: str = "-sV -O --top-ports 100"):
    """
    Wraps python-nmap to run version detection (-sV) and OS fingerprinting
    (-O) against a pre-authorized target. Returns a list of NmapHostResult.

    NOTE: -O requires the scanning process to run with raw-socket privileges
    (root / CAP_NET_RAW), same as the Scapy probes above.
    """
    try:
        import nmap
    except ImportError as exc:
        raise ScanExecutionError(
            "python-nmap is not installed. Install with `pip install python-nmap`, "
            "and ensure the `nmap` binary itself is installed and on PATH."
        ) from exc

    scanner = nmap.PortScanner(nmap_search_path=(settings.NMAP_PATH, "nmap"))
    try:
        scanner.scan(hosts=target, arguments=arguments, timeout=settings.SCAN_DEFAULT_TIMEOUT_SECONDS)
    except nmap.PortScannerError as exc:
        raise ScanExecutionError(f"Nmap execution failed: {exc}") from exc

    results = []
    for host_ip in scanner.all_hosts():
        host_data = scanner[host_ip]
        result = NmapHostResult(
            ip_address=host_ip,
            hostname=host_data.hostname() or "",
            state=host_data.state(),
        )

        os_matches = host_data.get("osmatch", [])
        if os_matches:
            best = os_matches[0]
            result.os_family = best.get("name", "")
            try:
                result.os_accuracy = int(best.get("accuracy", 0))
            except (TypeError, ValueError):
                result.os_accuracy = None

        for proto in host_data.all_protocols():
            for port_number, port_info in host_data[proto].items():
                if port_info.get("state") != "open":
                    continue
                result.ports.append({
                    "port": int(port_number),
                    "protocol": proto,
                    "service": port_info.get("name", ""),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "extrainfo": port_info.get("extrainfo", ""),
                })
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# Orchestration -- ties discovery + nmap together and persists to the DB
# ---------------------------------------------------------------------------
def execute_scan_job(job):
    """
    Runs a ScanJob end to end: authorization check -> discovery/port scan ->
    persistence -> hands off to the vulnerability correlation engine.
    Meant to be called from a Celery task or management command, not
    directly inside a web request (scans can take minutes).
    """
    from .models import DiscoveredHost, OpenPort, ScanJob

    job.status = ScanJob.Status.RUNNING
    job.started_at = timezone.now()
    job.scan_progress = 5
    job.save(update_fields=["status", "started_at", "scan_progress"])

    try:
        assert_authorized(job.target.ip_or_cidr)

        if job.scan_type == ScanJob.ScanType.DISCOVERY:
            if is_web_target(job.target.ip_or_cidr):
                raise ScanExecutionError(
                    "Host discovery (ARP/ICMP probing) doesn't apply to web hostnames/domains. "
                    "Use 'Web scan' or 'Port & service scan' for this target instead."
                )
            probes = discover_hosts(job.target.ip_or_cidr)
            job.scan_progress = 75
            job.save(update_fields=["scan_progress"])
            for probe in probes:
                if probe.is_up:
                    DiscoveredHost.objects.update_or_create(
                        job=job, ip_address=probe.ip_address,
                        defaults={"mac_address": probe.mac_address, "raw_probe_notes": probe.notes},
                    )
        else:
            job.scan_progress = 25
            job.save(update_fields=["scan_progress"])
            nmap_results = run_nmap_scan(job.target.ip_or_cidr, job.nmap_arguments)
            job.scan_progress = 75
            job.save(update_fields=["scan_progress"])
            for host_result in nmap_results:
                host_obj, _ = DiscoveredHost.objects.update_or_create(
                    job=job, ip_address=host_result.ip_address,
                    defaults={
                        "hostname": host_result.hostname,
                        "state": host_result.state,
                        "os_family": host_result.os_family,
                        "os_accuracy": host_result.os_accuracy,
                    },
                )
                for p in host_result.ports:
                    OpenPort.objects.update_or_create(
                        host=host_obj, port_number=p["port"], protocol=p["protocol"],
                        defaults={
                            "service_name": p["service"], "product": p["product"],
                            "version": p["version"], "extra_info": p["extrainfo"],
                        },
                    )

        job.status = ScanJob.Status.COMPLETED
        job.scan_progress = 100
        job.finished_at = timezone.now()
        score, label, reasons = calculate_attacker_risk(job)
        job.attacker_risk_score = score
        job.attacker_risk_label = label
        job.attacker_risk_reasons = reasons
        job.save(update_fields=[
            "status", "finished_at", "attacker_risk_score",
            "attacker_risk_label", "attacker_risk_reasons", "scan_progress",
        ])
        audit_logger.info("SCAN_COMPLETED job=%s target=%s", job.id, job.target.ip_or_cidr)

        # Hand off to the correlation engine (Module 3).
        from vulnassess.matcher import correlate_scan_job
        correlate_scan_job(job)

    except (UnauthorizedTargetError, ScanExecutionError, ValueError) as exc:
        job.status = ScanJob.Status.FAILED
        job.error_message = str(exc)
        job.finished_at = timezone.now()
        job.save(update_fields=["status", "error_message", "finished_at"])
        audit_logger.error("SCAN_FAILED job=%s error=%s", job.id, exc)
        raise
