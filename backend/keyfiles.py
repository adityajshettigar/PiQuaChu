# backend/keyfiles.py
"""
keyfiles.py — Key-Material Detection (PEM / DER / OpenSSH / PKCS#12)
====================================================================
Walks a directory tree for private-key / certificate / key-container files and
classifies the key algorithm:

  * PEM keys        (.pem, .key, .cer, .crt, .pub)  -> key-file-rsa / key-file-ec
  * OpenSSH private keys (-----BEGIN OPENSSH PRIVATE KEY-----) and public-key
    lines (ssh-rsa AAAA…, ssh-ed25519 AAAA…, ecdsa-sha2-… AAAA…) — including
    id_* / authorized_keys / known_hosts files
  * PKCS#12 / PFX containers (.p12, .pfx) via DER OID sniffing
  * PuTTY keys (.ppk) via the key-type markers

Algorithm detection is header-based plus a tiny DER scan for the well-known
X.509 AlgorithmIdentifier OIDs:

  RSA      1.2.840.113549.1.1.1   (06 09 2a 86 48 86 f7 0d 01 01 01)
  EC       1.2.840.10045.2.1      (06 07 2a 86 48 ce 3d 02 01)
  Ed25519  1.3.101.112            (06 03 2b 65 70)
  Ed448    1.3.101.113            (06 03 2b 65 71)
"""

import base64
import os
import re

# Rule ids defined in rules.yaml (metadata-only entries).
RSA_RULE = "key-file-rsa"
EC_RULE = "key-file-ec"

# PEM-style / text key extensions (incl. PuTTY .ppk).
KEY_EXTENSIONS = {".pem", ".key", ".cer", ".crt", ".pub", ".ppk"}
# Binary container formats (DER-based).
CONTAINER_EXTENSIONS = {".p12", ".pfx"}
# Files that hold SSH key material regardless of extension.
SSH_KEY_NAMES = {"authorized_keys", "known_hosts"}

_HEADER_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----", re.IGNORECASE
)

# OpenSSH public-key line: "ssh-rsa AAAA… comment"
_SSH_PUB_RE = re.compile(r"^\s*(ssh-rsa|ssh-ed25519|ecdsa-sha2-[^ ]+) ", re.M)

# Markers inside OpenSSH private key bodies / PuTTY keys.
_OPENSSH_HEADER = "OPENSSH PRIVATE KEY"
_SSH_RSA_MARKER = b"ssh-rsa"
_SSH_EC_MARKERS = (b"ssh-ed25519", b"ecdsa-sha2-")
_PPK_TYPE_RE = re.compile(r"^\s*PuTTY-User-Key-File-\d+:\s*(ssh-rsa|ssh-ed25519|ecdsa-sha2-[^ ]+)\s*$", re.M)

# Well-known X.509 AlgorithmIdentifier OIDs as DER bytes (searchable in the
# decoded PKCS#8 / SPKI / certificate / PKCS#12 body).
_OID_RSA = bytes.fromhex("06092a864886f70d010101")
_OID_EC = bytes.fromhex("06072a8648ce3d0201")
_OID_ED25519 = bytes.fromhex("06032b6570")
_OID_ED448 = bytes.fromhex("06032b6571")

_EXCLUDED_DIRS = {"venv", ".venv", "node_modules", ".git", "dist", "build",
                  "__pycache__", "site-packages", "target",
                  ".piquachu-backups", ".piquachu-patches"}

_MAX_HEADER_BYTES = 8192
_MAX_CONTAINER_BYTES = 65536


def _finding(path: str, rule: str, detail: str) -> dict:
    return {
        "file": path,
        "line": 1,
        "vulnerability": rule,
        "recommendation": (f"{detail} detected in {os.path.basename(path)}. "
                           f"Rotate to PQC key material and move to a secrets "
                           f"manager / HSM."),
        "severity": "ERROR",
    }


def _decode_body(head_text: str, match) -> bytes:
    """Base64-decode the PEM body between the BEGIN header and the closing
    marker line (enough to sniff OIDs / OpenSSH markers)."""
    body_start = match.end()
    body_end = head_text.find("\n-----", body_start)
    if body_end == -1:
        return b""
    b64 = head_text[body_start:body_end]
    try:
        return base64.b64decode(re.sub(r"\s+", "", b64))
    except Exception:
        return b""


def _classify_pem(header: str, der_body: bytes) -> str | None:
    """Classify a PEM header + decoded DER body."""
    h = header.lower()
    if "rsa private key" in h:
        return RSA_RULE
    if "ec private key" in h:
        return EC_RULE
    if "private key" in h or "public key" in h or "certificate" in h:
        # PKCS#8 / SPKI / X.509 — sniff the algorithm OID inside the DER.
        if _OID_RSA in der_body:
            return RSA_RULE
        if _OID_EC in der_body or _OID_ED25519 in der_body or _OID_ED448 in der_body:
            return EC_RULE
    return None


def _scan_pem_text(path: str, head: bytes) -> dict | None:
    """PEM / plain-text key file: PEM headers, OpenSSH keys, SSH pub lines."""
    try:
        head_text = head.decode("utf-8", errors="replace")
    except Exception:
        return None

    match = _HEADER_RE.search(head_text)
    if match:
        der_body = _decode_body(head_text, match)
        rule = _classify_pem(match.group(1), der_body)
        if rule:
            return _finding(path, rule, match.group(1) + " key material")

    # OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----).
    if _OPENSSH_HEADER in head_text:
        body = _decode_body(head_text, match) if match else head
        if _SSH_RSA_MARKER in body:
            return _finding(path, RSA_RULE, "OpenSSH RSA private key")
        if any(m in body for m in _SSH_EC_MARKERS):
            return _finding(path, EC_RULE, "OpenSSH EC/EdDSA private key")

    # OpenSSH public-key line (authorized_keys / .pub / id_*.pub).
    pub = _SSH_PUB_RE.search(head_text)
    if pub:
        prefix = pub.group(1)
        if prefix == "ssh-rsa":
            return _finding(path, RSA_RULE, "SSH RSA public key")
        return _finding(path, EC_RULE, f"SSH {prefix} public key")

    # PuTTY private key.
    ppk = _PPK_TYPE_RE.search(head_text)
    if ppk:
        key_type = ppk.group(1)
        if key_type == "ssh-rsa":
            return _finding(path, RSA_RULE, "PuTTY RSA private key")
        return _finding(path, EC_RULE, f"PuTTY {key_type} private key")
    return None


def _scan_container(path: str, head: bytes) -> dict | None:
    """PKCS#12 / PFX binary containers: sniff embedded X.509 algorithm OIDs."""
    for oid, rule in ((_OID_RSA, RSA_RULE), (_OID_EC, EC_RULE),
                      (_OID_ED25519, EC_RULE), (_OID_ED448, EC_RULE)):
        if oid in head:
            label = "RSA" if rule == RSA_RULE else "EC/EdDSA"
            return _finding(path, rule, f"PKCS#12 / PFX container with {label} key material")
    return None


def scan_keyfiles(target_directory: str) -> list:
    """Walk target_directory for key/cert/container files and return findings."""
    findings = []
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for name in files:
            path = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            base = name.lower()

            if ext in CONTAINER_EXTENSIONS:
                try:
                    with open(path, "rb") as fh:
                        head = fh.read(_MAX_CONTAINER_BYTES)
                except OSError:
                    continue
                finding = _scan_container(path, head) if head else None
            elif ext in KEY_EXTENSIONS or base.startswith("id_") or base in SSH_KEY_NAMES:
                try:
                    with open(path, "rb") as fh:
                        head = fh.read(_MAX_HEADER_BYTES)
                except OSError:
                    continue
                if not head or (head.startswith(b"\x00") and b"\x00" * 8 in head[:256]):
                    continue  # empty or non-PEM binary (out of scope here)
                finding = _scan_pem_text(path, head)
            else:
                continue

            if finding:
                findings.append(finding)
    return findings


def scan_target(target_directory: str) -> list:
    """Public entry point used by scanner.scan_directory()."""
    return scan_keyfiles(target_directory)
