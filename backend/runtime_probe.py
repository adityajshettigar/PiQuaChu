# backend/runtime_probe.py
"""
runtime_probe.py — opt-in, read-only runtime evidence (MVP)
===========================================================
Static scanning cannot see what a running process actually loaded. This module
adds a *separate* evidence source for that, deliberately narrow:

  * **Opt-in**: ``collect(enable=False)`` refuses. The CLI subcommand requires
    ``--enable``. Nothing is collected at import time, on a schedule or by the
    API.
  * **Read-only**: no process memory, no ``/proc/<pid>/mem``, no private keys,
    no credentials, no code execution, no ``ldd`` on untrusted binaries, no
    package installation and no daemon.
  * **Authorized targets only**: the current interpreter, or an explicit PID
    owned by the same UID. Root/other-UID PIDs are refused, PID 1 is refused.
  * **No network by default**: a live TLS probe requires an explicit target AND
    an explicit ``allow_live_probe``; otherwise the field says ``not_collected``.
  * **Honest absence**: a missing permission is ``not_collected`` with a reason,
    never "no crypto found".

Evidence items carry ``source: "runtime"`` so they can sit beside static
findings (``source: "static"``) without being conflated. Java evidence is split
into two distinct claims:

  * ``java_configured_classpath`` — what the command line *asked for* (low
    confidence, never proof of use);
  * ``java_loaded_classes`` — what the JVM actually loaded, read through a
    bounded, same-UID ``jcmd VM.class_hierarchy`` attach (high confidence).

A JRE without ``jcmd``, a disabled attach mechanism or a different UID yields
``not_collected``/``error`` with the reason — never "no crypto loaded".
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = 1
EVIDENCE_SOURCE = "runtime"

_CRYPTO_PACKAGES = (
    "cryptography", "pyopenssl", "pycryptodome", "cryptography-legacy",
    "paramiko", "pyjwt", "bcrypt", "oqs", "liboqs-python", "pynacl",
    "requests", "urllib3",
)

MAX_MODULES = 400
MAX_SO_PATHS = 300
MAX_CLASSPATH_ENTRIES = 100

# Java loaded-class evidence (jcmd attach). Bounded in time and in retained
# output; the raw jcmd stream is never stored, only class *names* from known
# crypto namespaces.
JCMD_TIMEOUT_S = 15
MAX_JCMD_BYTES = 8 * 1024 * 1024
MAX_LOADED_CLASS_EVIDENCE = 60
MAX_LOADED_CLASSES_SCANNED = 200_000
_CRYPTO_CLASS_PREFIXES = (
    "javax.crypto", "java.security", "com.sun.crypto.provider", "sun.security",
    "org.bouncycastle", "org.apache.commons.crypto", "com.google.crypto.tink",
    "org.conscrypt", "io.netty.handler.ssl",
)
_HIERARCHY_LINE_RE = re.compile(
    r"^[\s|+\\-]*(?:class\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)")
_JAVA_MAIN_RE = re.compile(r"(^|/)(java|javaw)(\.[A-Za-z0-9_.-]+)?$")


class RuntimeProbeError(Exception):
    """Base class for runtime-evidence refusals."""


class RuntimeProbeDisabled(RuntimeProbeError):
    """Raised when collection was not explicitly enabled."""


class RuntimeProbeDenied(RuntimeProbeError):
    """Raised when the target PID is not authorized."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _item(*, evidence_type: str, name: str, status: str, method: str,
          version: str | None = None, confidence: str = "medium",
          detail: str | None = None, limitations: str | None = None,
          path: str | None = None) -> dict:
    item = {
        "evidence_source": EVIDENCE_SOURCE,
        "evidence_type": evidence_type,
        "name": name,
        "status": status,              # collected | not_collected | denied | error
        "method": method,
        "confidence": confidence,
        "collected_at": _now(),
    }
    if version:
        item["version"] = version
    if detail:
        item["detail"] = detail
    if limitations:
        item["limitations"] = limitations
    if path:
        item["path"] = path
    return item


def _normalize(name: str) -> str:
    """Library/package name → dashed lowercase (best effort, no imports)."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def _python_evidence() -> tuple[list[dict], dict]:
    items: list[dict] = [
        _item(evidence_type="python_runtime", name="python", status="collected",
              method="sys.version (current interpreter)",
              version=platform.python_version(), confidence="high"),
    ]
    modules = sorted(name for name in list(sys.modules)[:MAX_MODULES] if name)
    items.append(_item(
        evidence_type="runtime_module_names", name="python.loaded_modules",
        status="collected", method="sys.modules (names only, no object memory)",
        detail=", ".join(modules[:MAX_MODULES]),
        confidence="high",
        limitations="Names of modules imported by this interpreter; not a "
                    "complete catalogue of every process on the host."))

    coverage = {"python_modules": "collected"}

    # Distribution versions come from package metadata, never by importing the
    # scanned target's code.
    try:
        from importlib import metadata
        installed: dict[str, str] = {}
        for name in _CRYPTO_PACKAGES:
            try:
                installed[_normalize(name)] = metadata.version(name)
            except Exception:
                continue
        items.append(_item(
            evidence_type="runtime_packages", name="python.crypto_packages",
            status="collected" if installed else "not_collected",
            method="importlib.metadata.version (no import of scanned code)",
            detail=", ".join(f"{k}=={v}" for k, v in sorted(installed.items())) or None,
            confidence="high",
            limitations="Only allowlisted crypto-relevant distributions are reported."))
    except Exception as exc:  # noqa: BLE001
        items.append(_item(evidence_type="runtime_packages",
                           name="python.crypto_packages", status="error",
                           method="importlib.metadata.version",
                           detail=type(exc).__name__, confidence="low"))
        coverage["python_packages"] = "error"
    return items, coverage


def _looks_like_jvm(args: list[str]) -> bool:
    """Heuristic: a JVM command line starts with java/javaw (or -X/-jar)."""
    if not args:
        return False
    if _JAVA_MAIN_RE.search(args[0].replace("\\", "/")):
        return True
    return any(arg.startswith(("-X", "-jar", "-Djava.")) for arg in args[:5])


def _parse_loaded_classes(text: str) -> tuple[int, list[str]]:
    """Extract class names from `jcmd VM.class_hierarchy` output.

    Only names from known cryptographic namespaces are retained; everything
    else is counted and discarded so the evidence stays small and free of
    application/secret-bearing identifiers.
    """
    total = 0
    crypto: set[str] = set()
    for line in text.splitlines():
        if total >= MAX_LOADED_CLASSES_SCANNED:
            break
        match = _HIERARCHY_LINE_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        total += 1
        if name.startswith(_CRYPTO_CLASS_PREFIXES):
            crypto.add(name)
    return total, sorted(crypto)[:MAX_LOADED_CLASS_EVIDENCE]


def _java_loaded_classes(pid: int) -> dict:
    """Loaded classes in a running JVM, via a bounded `jcmd` attach.

    Read-only: `VM.class_hierarchy` enumerates loaded classes and triggers no
    GC, no code execution and no memory/attribute dump. Requires a JDK (jcmd),
    the same UID as the target and an enabled attach mechanism; every failure
    is reported as `not_collected`/`error`, never as "no crypto loaded".
    """
    base = dict(evidence_type="java_loaded_classes", name="java.loaded_classes")
    limitations = ("Classes actually loaded by the JVM at collection time. "
                   "Only names from known crypto namespaces are retained; this "
                   "is not a call graph, a key inventory or proof of use.")
    jcmd = shutil.which("jcmd")
    if not jcmd:
        return _item(**base, status="not_collected",
                     method="jcmd (JDK diagnostic tool)", confidence="low",
                     detail="jcmd is not installed (JRE-only runtime or not on PATH)",
                     limitations=limitations)
    try:
        proc = subprocess.run([jcmd, str(pid), "VM.class_hierarchy", "-i", "-s"],
                              capture_output=True, timeout=JCMD_TIMEOUT_S,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return _item(**base, status="error", method="jcmd VM.class_hierarchy",
                     confidence="low",
                     detail=f"jcmd timed out after {JCMD_TIMEOUT_S}s",
                     limitations=limitations)
    except OSError as exc:
        return _item(**base, status="error", method="jcmd VM.class_hierarchy",
                     confidence="low", detail=f"jcmd could not run ({type(exc).__name__})",
                     limitations=limitations)
    if proc.returncode != 0:
        return _item(**base, status="not_collected",
                     method="jcmd VM.class_hierarchy", confidence="low",
                     detail=f"attach refused or unsupported (jcmd exit "
                            f"{proc.returncode})",
                     limitations=limitations)
    text = proc.stdout[:MAX_JCMD_BYTES].decode("utf-8", "replace")
    truncated = len(proc.stdout) >= MAX_JCMD_BYTES
    total, crypto = _parse_loaded_classes(text)
    if not total:
        return _item(**base, status="not_collected",
                     method="jcmd VM.class_hierarchy", confidence="low",
                     detail="jcmd returned no class hierarchy",
                     limitations=limitations)
    detail = (f"{len(crypto)} crypto-related class(es) loaded of {total} "
              f"class(es) scanned")
    item = _item(**base, status="collected", method="jcmd VM.class_hierarchy "
                                                    "-i -s (same-UID attach)",
                 confidence="high", detail=detail, limitations=limitations)
    item["loaded_classes_total"] = total
    item["crypto_classes"] = crypto
    item["truncated"] = truncated
    return item


def _pid_authorized(pid: int) -> None:
    if not isinstance(pid, int) or pid <= 1:
        raise RuntimeProbeDenied(
            "Refusing PID 1/0/invalid targets: only an explicitly authorized "
            "application PID can be inspected.")
    proc = f"/proc/{pid}"
    if not os.path.isdir(proc):
        raise RuntimeProbeDenied(f"No such process: {pid}")
    if hasattr(os, "getuid"):
        try:
            owner = os.stat(proc).st_uid
        except OSError as exc:
            raise RuntimeProbeDenied(f"Cannot stat process {pid}: {type(exc).__name__}")
        if owner != os.getuid():
            raise RuntimeProbeDenied(
                "Process is owned by another user; refusing (no sudo/root probe).")


def _read_so_paths(maps_path: str) -> list[str]:
    """Extract loaded shared-object *paths* from a readable maps file.

    Reads paths only; never memory contents or environment/credentials.
    """
    paths: list[str] = []
    try:
        with open(maps_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split()
                if not parts:
                    continue
                candidate = parts[-1]
                if candidate.startswith("/") and (".so" in candidate):
                    if candidate not in paths:
                        paths.append(candidate)
                if len(paths) >= MAX_SO_PATHS:
                    break
    except PermissionError:
        raise
    except OSError as exc:
        raise RuntimeProbeError(type(exc).__name__)
    return paths


def _pid_evidence(pid: int) -> tuple[list[dict], dict, list[str]]:
    items: list[dict] = []
    coverage: dict = {}
    errors: list[str] = []
    _pid_authorized(pid)

    maps_path = f"/proc/{pid}/maps"
    try:
        paths = _read_so_paths(maps_path)
        items.append(_item(
            evidence_type="loaded_shared_objects", name=f"pid{pid}.maps",
            status="collected" if paths else "not_collected",
            method="/proc/<pid>/maps (path column only — no memory contents)",
            detail=", ".join(paths[:MAX_SO_PATHS]) or "no shared-object paths",
            confidence="high",
            limitations="Only libraries the kernel mapped for this process; "
                        "path availability depends on /proc permissions."))
        coverage["loaded_shared_objects"] = "collected"
    except PermissionError:
        items.append(_item(
            evidence_type="loaded_shared_objects", name=f"pid{pid}.maps",
            status="not_collected", method="/proc/<pid>/maps",
            detail="permission denied (hidepid or missing ptrace access)",
            confidence="low",
            limitations="Not collected is not evidence that no crypto is loaded."))
        coverage["loaded_shared_objects"] = "not_collected: permission"
        errors.append("maps_permission_denied")
    except RuntimeProbeError as exc:
        coverage["loaded_shared_objects"] = "error"
        errors.append(f"maps_error:{exc}")

    # Java: classpath is *configured*, not proof of use.
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read(64 * 1024)
        args = [part.decode("utf-8", "replace") for part in raw.split(b"\x00") if part]
        classpath = None
        for index, arg in enumerate(args):
            if arg in {"-cp", "-classpath", "--class-path"} and index + 1 < len(args):
                classpath = args[index + 1]
                break
            if arg.startswith("--class-path="):
                classpath = arg.split("=", 1)[1]
                break
        if classpath:
            entries = [entry for entry in classpath.split(os.pathsep)
                       if entry][:MAX_CLASSPATH_ENTRIES]
            items.append(_item(
                evidence_type="java_configured_classpath", name="java.classpath",
                status="collected", method="/proc/<pid>/cmdline (-cp/-classpath)",
                detail=", ".join(entries), confidence="low",
                limitations="CONFIGURED classpath only — this does not prove any "
                            "entry was loaded or used. Loaded classes are "
                            "reported separately (jcmd)."))
            coverage["java_configured_classpath"] = "collected"
        else:
            items.append(_item(
                evidence_type="java_configured_classpath", name="java.classpath",
                status="not_collected", method="/proc/<pid>/cmdline",
                detail="no -cp/--class-path entry in the command line",
                confidence="low",
                limitations="Absence of a classpath flag is not absence of Java."))
            coverage["java_configured_classpath"] = "not_collected: no classpath"
        if _looks_like_jvm(args):
            loaded = _java_loaded_classes(pid)
        else:
            loaded = _item(
                evidence_type="java_loaded_classes", name="java.loaded_classes",
                status="not_collected", method="jcmd (not attempted)",
                confidence="low",
                detail="target process does not look like a JVM",
                limitations="Classpath presence never implies the library was "
                            "loaded; no JVM was detected for this PID.")
        items.append(loaded)
        coverage["java_loaded_classes"] = (
            loaded["status"] if loaded["status"] != "collected"
            else "collected")
        if loaded["status"] != "collected":
            errors.append(f"java_loaded_classes:{loaded['status']}")
    except (OSError, IndexError) as exc:
        coverage["java_configured_classpath"] = "error"
        errors.append(f"cmdline_error:{type(exc).__name__}")

    return items, coverage, errors


def _live_tls_evidence(host: str, port: int) -> dict:
    """Explicit live probe (opt-in + explicit target). No scanning, one host."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, int(port)), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return _item(
                    evidence_type="tls_negotiated", name=f"{host}:{port}",
                    status="collected", method="single explicit TLS handshake",
                    detail=f"protocol={tls.version()} cipher={tls.cipher()[0]}",
                    confidence="high",
                    limitations="One explicit target only; negotiated parameters "
                                "do not describe the rest of the estate.")
    except (OSError, ssl.SSLError) as exc:
        return _item(evidence_type="tls_negotiated", name=f"{host}:{port}",
                     status="error", method="single explicit TLS handshake",
                     detail=type(exc).__name__, confidence="low")


def _tls_default_evidence() -> dict:
    openssl = ssl.OPENSSL_VERSION
    return _item(
        evidence_type="tls_runtime_library", name="openssl",
        status="collected", method="ssl.OPENSSL_VERSION (current interpreter)",
        detail=openssl, confidence="high")


def collect(*, enable: bool = False, pid: int | None = None,
            live_tls_target: str | None = None,
            allow_live_probe: bool = False,
            include_python: bool = True) -> dict:
    """Collect read-only runtime evidence.

    ``enable`` must be True; that is the opt-in gate. ``pid`` selects an
    authorized process (same UID). ``live_tls_target`` (host:port) is contacted
    only when ``allow_live_probe`` is also True.
    """
    if not enable:
        raise RuntimeProbeDisabled(
            "Runtime discovery is opt-in. Re-run with --enable (CLI) or "
            "collect(enable=True).")

    result = {
        "schema_version": SCHEMA_VERSION,
        "evidence_source": EVIDENCE_SOURCE,
        "collected_at": _now(),
        "read_only": True,
        "network_used": False,
        "memory_inspected": False,
        "host": {
            "platform": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "uid": getattr(os, "getuid", lambda: None)(),
            "is_root": bool(getattr(os, "geteuid", lambda: 1)() == 0),
        },
        "permissions": {
            "scope": "current user; no sudo/root escalation",
            "root_required": False,
            "pid": pid,
        },
        "coverage": {},
        "errors": [],
        "items": [],
        "limitations": [
            "Runtime evidence describes only the inspected process at one moment.",
            "A missing permission or failed read is reported as not_collected.",
            "Java classpath entries are configured paths, not loaded classes; "
            "loaded-class evidence requires a same-UID JVM with jcmd attach.",
            "No process memory, secrets, credentials or private keys are read.",
        ],
    }
    coverage: dict = result["coverage"]

    if include_python:
        items, py_coverage = _python_evidence()
        result["items"].extend(items)
        coverage.update(py_coverage)

    result["items"].append(_tls_default_evidence())
    coverage["tls_runtime_library"] = "collected"

    if pid is not None:
        try:
            items, pid_coverage, errors = _pid_evidence(int(pid))
            result["items"].extend(items)
            coverage.update(pid_coverage)
            result["errors"].extend(errors)
        except RuntimeProbeDenied as exc:
            raise
        except RuntimeProbeError as exc:
            result["errors"].append(f"pid_probe:{type(exc).__name__}")

    if live_tls_target:
        host, _, port = live_tls_target.partition(":")
        if not allow_live_probe:
            result["items"].append(_item(
                evidence_type="tls_negotiated", name=live_tls_target,
                status="not_collected", method="live handshake not enabled",
                confidence="low",
                limitations="Pass --allow-live-probe with an explicit target to "
                            "contact this one host. No network call was made."))
            coverage["tls_negotiated"] = "not_collected: opt-in required"
        elif not host or not port.isdigit():
            result["items"].append(_item(
                evidence_type="tls_negotiated", name=live_tls_target,
                status="error", method="invalid target",
                detail="expected host:port", confidence="low"))
            result["errors"].append("invalid_tls_target")
        else:
            result["items"].append(_live_tls_evidence(host, int(port)))
            result["network_used"] = True
            coverage["tls_negotiated"] = "collected"
    else:
        result["items"].append(_item(
            evidence_type="tls_negotiated", name="tls.negotiated",
            status="not_collected", method="no target provided",
            confidence="low",
            limitations="No live probe configured; static config scanning is a "
                        "separate evidence source."))
        coverage["tls_negotiated"] = "not_collected: no target"

    result["summary"] = {
        "collected": sum(1 for item in result["items"] if item["status"] == "collected"),
        "not_collected": sum(1 for item in result["items"]
                             if item["status"] == "not_collected"),
        "errors": sum(1 for item in result["items"] if item["status"] == "error"),
    }
    return result
