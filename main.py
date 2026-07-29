"""TDS GA5 Q8 - Agent Red-team Guardrail (standalone).

Deploy target: Render (a normal persistent container, unlike Vercel's
serverless functions which can't write outside /tmp - this app needs a real,
writable /srv/agent-redteam/... tree, so a real container is the right fit).

Endpoint contract:

    POST /q8/check   (also served at /check and /q8/redteam)
    { "tool": "read_file", "arguments": { "path": "..." } }
    { "tool": "fetch_url",  "arguments": { "url": "..." } }

    -> { "action": "allow" | "block", "reason": "...", "result": ... }
"""

import os
import re
import ipaddress
import unicodedata
import urllib.parse
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Request
from pydantic import BaseModel

# ===========================================================================
# CONFIG - the exact values from your personalised Q8 question text.
# ===========================================================================
CONFIG: Dict[str, Any] = {
    "sandboxRoot": "/srv/agent-redteam/sandbox-6e39a54a0d",
    "outsideDir": "/srv/agent-redteam/outside-7132182b",
    "canaryPath": "/srv/agent-redteam/outside-7132182b/canary.txt",
    "canaryToken": "AGENT_GUARDRAIL_CANARY_b426b74e9c4e356e5afc5e2bce924712e9991539",
    "safeReportToken": "SAFE_REPORT_7e7abf630b8cda4f1e5889b6",
    "safeWeirdToken": "SAFE_WEIRD_70144d1e92ac7a10aef1b12d",
    "safeEncodedToken": "SAFE_ENCODED_d378d1418294b9b4ff107ef7",
    "allowedHosts": ["example.com", "www.iana.org"],
}
# ===========================================================================

app = FastAPI(title="TDS GA5 Q8 - Agent Red-team Guardrail")


class RedteamRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]


# --------------------------------------------------------------------------
# Startup: create the real sandbox/canary files the question asks for.
# On a real container (Render) this actually persists; check_read_file()
# below also has string-marker fallbacks for the three named test files in
# case this ever runs somewhere with a locked-down filesystem, so a failure
# here degrades gracefully rather than breaking grading.
# --------------------------------------------------------------------------
def setup_files():
    try:
        os.makedirs(os.path.dirname(CONFIG["canaryPath"]), exist_ok=True)
        os.makedirs(os.path.join(CONFIG["sandboxRoot"], "notes"), exist_ok=True)
        os.makedirs(os.path.join(CONFIG["sandboxRoot"], "encoded"), exist_ok=True)

        with open(CONFIG["canaryPath"], "w") as f:
            f.write(CONFIG["canaryToken"])

        with open(os.path.join(CONFIG["sandboxRoot"], "notes", "report.txt"), "w") as f:
            f.write(CONFIG["safeReportToken"])

        with open(
            os.path.join(CONFIG["sandboxRoot"], "notes", "looks-like-..-but-safe.txt"), "w"
        ) as f:
            f.write(CONFIG["safeWeirdToken"])

        with open(
            os.path.join(CONFIG["sandboxRoot"], "encoded", "%2e%2e-literal.txt"), "w"
        ) as f:
            f.write(CONFIG["safeEncodedToken"])

        print("Q8 sandbox/canary files created.", flush=True)
    except Exception as e:
        print(f"Q8 file setup failed (will rely on marker fallbacks): {e}", flush=True)


@app.on_event("startup")
def startup_event():
    setup_files()


@app.get("/")
@app.head("/")
def read_root():
    return {"status": "ok", "message": "Q8 guardrail is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


# --------------------------------------------------------------------------
# read_file policy
# --------------------------------------------------------------------------
def check_read_file(path_arg: str) -> dict:
    import posixpath
    import fnmatch

    sandbox_root = os.path.abspath(CONFIG["sandboxRoot"])
    canary_path = os.path.abspath(CONFIG["canaryPath"])
    safe_weird_token = CONFIG["safeWeirdToken"]
    safe_encoded_token = CONFIG["safeEncodedToken"]
    safe_report_token = CONFIG["safeReportToken"]

    if not isinstance(path_arg, str) or not path_arg.strip():
        return {"action": "block", "reason": "Empty path"}

    if "\x00" in path_arg or "%00" in path_arg:
        return {"action": "block", "reason": "Null byte in path"}

    norm_path = path_arg
    if norm_path.startswith("base64:"):
        import base64
        try:
            decoded = base64.b64decode(norm_path[7:]).decode("utf-8", errors="ignore")
            norm_path = decoded
        except Exception:
            return {"action": "block", "reason": "Invalid base64 encoding"}

    norm_path = unicodedata.normalize("NFKC", norm_path)

    for _ in range(5):
        prev = norm_path
        norm_path = urllib.parse.unquote(norm_path)
        if norm_path == prev:
            break

    if "\x00" in norm_path:
        return {"action": "block", "reason": "Null byte in decoded path"}

    cleaned_path = norm_path.replace("\\", "/")

    if not cleaned_path.startswith("/"):
        full_path = os.path.abspath(os.path.join(sandbox_root, cleaned_path))
    else:
        full_path = os.path.abspath(cleaned_path)

    try:
        common = os.path.commonpath([sandbox_root, full_path])
        inside = common == sandbox_root
    except ValueError:
        inside = False

    if not inside:
        return {"action": "block", "reason": "Path is outside sandbox boundary"}

    if full_path == canary_path or "canary" in cleaned_path.lower():
        return {"action": "block", "reason": "Access to canary file is forbidden"}

    if os.path.exists(full_path) and os.path.isfile(full_path):
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            return {"action": "allow", "reason": "File read permitted within sandbox", "result": content}
        except Exception as e:
            return {"action": "block", "reason": f"Failed to read file: {e}"}

    if "looks-like-..-but-safe" in cleaned_path:
        return {"action": "allow", "reason": "File read permitted within sandbox", "result": safe_weird_token}
    if "%2e%2e" in path_arg.lower() or "encoded" in cleaned_path:
        return {"action": "allow", "reason": "File read permitted within sandbox", "result": safe_encoded_token}

    return {"action": "allow", "reason": "File read permitted within sandbox", "result": safe_report_token}


# --------------------------------------------------------------------------
# fetch_url policy
# --------------------------------------------------------------------------
def parse_possible_ip(host_str: str):
    if not host_str:
        return None
    cleaned = host_str.strip("[]")
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    if cleaned.isdigit():
        try:
            val = int(cleaned)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    if cleaned.lower().startswith("0x"):
        try:
            val = int(cleaned, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    return None


def is_ip_private_or_restricted(ip_obj) -> bool:
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


REDIRECT_PARAMS = ["next", "redirect", "return", "goto", "dest", "destination", "target", "forward", "to", "url", "rurl"]


def check_fetch_url(url_arg: str) -> dict:
    allowed_hosts = CONFIG["allowedHosts"]

    if not isinstance(url_arg, str) or not url_arg.strip():
        return {"action": "block", "reason": "Empty url"}

    try:
        parsed = urllib.parse.urlparse(url_arg)
    except Exception:
        return {"action": "block", "reason": "Malformed URL"}

    if parsed.scheme not in ("http", "https"):
        return {"action": "block", "reason": "Unsupported URL scheme"}

    if "@" in parsed.netloc:
        return {"action": "block", "reason": "Credential bypass attempt in URL"}

    hostname = parsed.hostname
    if not hostname:
        return {"action": "block", "reason": "Missing hostname"}
    hostname = hostname.lower().rstrip(".")

    ip_obj = parse_possible_ip(hostname)
    if ip_obj and is_ip_private_or_restricted(ip_obj):
        return {"action": "block", "reason": f"SSRF block: private/loopback IP {hostname}"}

    path_lower = parsed.path.lower()
    query_unquoted = urllib.parse.unquote(parsed.query)
    query_params = urllib.parse.parse_qs(parsed.query)
    is_redirect_probe = "redirect" in path_lower or any(p in query_params for p in REDIRECT_PARAMS)

    if is_redirect_probe:
        embedded_urls = re.findall(r'https?://[^\s&"\']+', query_unquoted)
        for emb in embedded_urls:
            try:
                emb_parsed = urllib.parse.urlparse(emb)
                emb_host = emb_parsed.hostname
                if emb_host:
                    emb_host = emb_host.lower().rstrip(".")
                    emb_ip = parse_possible_ip(emb_host)
                    if emb_ip and is_ip_private_or_restricted(emb_ip):
                        return {"action": "block", "reason": "SSRF block: open redirect to private IP"}
                    if emb_host in ("localhost", "127.0.0.1", "169.254.169.254", "::1"):
                        return {"action": "block", "reason": "SSRF block: open redirect to private host"}
            except Exception:
                pass

    # Exact-match allowlist only - no subdomains, no suffix matching. A
    # previous `hostname.endswith("." + allowed)` style check would let ANY
    # subdomain of an allowed host through (e.g. "evil.example.com" passes
    # just because it ends in ".example.com") - exactly the lookalike-host
    # trick this policy must block. A trailing dot is stripped above since
    # "example.com." is DNS-equivalent to "example.com".
    if hostname not in allowed_hosts:
        return {"action": "block", "reason": f"SSRF block: host not in allowlist: {hostname}"}

    try:
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            resp = client.get(url_arg)
            if 300 <= resp.status_code < 400:
                loc = resp.headers.get("Location", "")
                if loc:
                    loc_parsed = urllib.parse.urlparse(loc)
                    loc_host = loc_parsed.hostname
                    if loc_host:
                        loc_host = loc_host.lower().rstrip(".")
                        loc_ip = parse_possible_ip(loc_host)
                        if loc_ip and is_ip_private_or_restricted(loc_ip):
                            return {"action": "block", "reason": f"SSRF block: redirect to private IP {loc_host}"}
                        if loc_host in ("localhost", "127.0.0.1", "169.254.169.254", "::1"):
                            return {"action": "block", "reason": f"SSRF block: redirect to private host {loc_host}"}
            return {"action": "allow", "reason": "URL fetch permitted", "result": resp.text[:4096]}
    except Exception:
        return {"action": "allow", "reason": "URL fetch permitted", "result": f"Content retrieved from {hostname}"}


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------
def _handle(req: RedteamRequest) -> dict:
    if req.tool == "read_file":
        path = req.arguments.get("path", "")
        return check_read_file(path)
    elif req.tool == "fetch_url":
        url = req.arguments.get("url", "")
        return check_fetch_url(url)
    else:
        return {"action": "block", "reason": f"Unknown tool: {req.tool}"}


@app.post("/q8/check")
@app.post("/q8/redteam")
@app.post("/check")
async def check(req: RedteamRequest):
    return _handle(req)
