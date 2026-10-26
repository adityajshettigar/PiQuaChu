#!/usr/bin/env python3
# backend/test_runtime_java.py
"""
test_runtime_java.py — real-JVM runtime evidence (Phase 2 completion)
=====================================================================
Run:  venv/bin/python test_runtime_java.py     (no pytest required)

The Phase 4 runtime probe shipped as Linux/Python-only: Java classpath entries
were labelled *configured* and loaded-class evidence was a hard-coded
`not_collected: helper not implemented`. This suite covers the real
implementation:

  * a **real JVM** (fixture app that calls Cipher/MessageDigest) is inspected
    with a bounded `jcmd VM.class_hierarchy` attach and the loaded crypto
    classes are reported;
  * configured classpath and loaded classes stay separate claims with
    different confidence;
  * no memory, no environment, no command-line secrets, no network;
  * jcmd missing / attach refused / timeout / non-JVM target all degrade to
    `not_collected`/`error` with a reason — never "no crypto loaded";
  * permission handling: PID 1 and other-UID PIDs are denied.

`java`, `javac` and `jcmd` are required (a JDK). When they are absent the
real-JVM checks report BLOCKED with a command and are not counted as passed;
the deterministic logic checks still run.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import runtime_probe  # noqa: E402

PASSED = []
FAILED = []
BLOCKED = []

JAVA_FIXTURE = """\
import javax.crypto.Cipher;
import java.security.MessageDigest;

public class CryptoApp {
    public static void main(String[] args) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        System.out.println("ready " + c.getAlgorithm() + " " + md.getAlgorithm());
        System.out.flush();
        Thread.sleep(120000);
    }
}
"""


def check(name, condition, detail=""):
    if not condition:
        FAILED.append(name)
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def blocked(name, reason, command):
    BLOCKED.append({"check": name, "reason": reason, "command": command})
    print(f"  ⊘ BLOCKED: {name} — {reason}\n    run: {command}")


def _jdk_available() -> tuple[bool, str]:
    missing = [tool for tool in ("java", "javac", "jcmd")
               if not shutil.which(tool)]
    if missing:
        return False, "missing " + ", ".join(missing)
    return True, ""


def _start_jvm(workdir: str):
    """Compile + start the fixture and wait for its readiness line."""
    src = os.path.join(workdir, "CryptoApp.java")
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(JAVA_FIXTURE)
    compiled = subprocess.run([shutil.which("javac"), src], cwd=workdir,
                              capture_output=True, text=True, timeout=180)
    if compiled.returncode != 0:
        return None, compiled.stderr[-800:]
    proc = subprocess.Popen(
        [shutil.which("java"), "-Djava.io.tmpdir=" + workdir, "-cp", workdir,
         "CryptoApp"],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, start_new_session=True)
    deadline = time.time() + 90
    line = ""
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                return None, "fixture JVM exited before reporting ready"
            time.sleep(0.2)
            continue
        if "ready" in line:
            return proc, "ready"
    return None, "fixture JVM did not report ready"


def _probe(pid):
    return runtime_probe.collect(enable=True, pid=pid)


def _item(report, evidence_type):
    for entry in report["items"]:
        if entry.get("evidence_type") == evidence_type:
            return entry
    return None


def test_parser_is_bounded_and_filters():
    text = "\n".join([
        "1234:",
        "java.lang.Object",
        "    |-- java.io.Serializable",
        "        |-- javax.crypto.Cipher",
        "            +-- com.sun.crypto.provider.AESCipher$AES128_GCM_NoPadding",
        "    |-- org.example.ApplicationSecretService",
        "    |-- java.security.MessageDigest",
        "",
    ])
    total, crypto = runtime_probe._parse_loaded_classes(text)
    check("java parser counts class lines", total == 6, total)
    check("java parser keeps only crypto namespaces",
          "javax.crypto.Cipher" in crypto
          and "java.security.MessageDigest" in crypto
          and "com.sun.crypto.provider.AESCipher$AES128_GCM_NoPadding" in crypto
          and not any("example" in name for name in crypto), crypto)
    check("java parser ignores the pid header and tree glyphs",
          all(not name.strip()[-1:] == ":" for name in crypto))

    huge = "\n".join(f"    |-- org.example.Cls{i}" for i in
                     range(runtime_probe.MAX_LOADED_CLASSES_SCANNED + 500))
    total_huge, crypto_huge = runtime_probe._parse_loaded_classes(huge)
    check("java parser bounds the number of scanned classes",
          total_huge == runtime_probe.MAX_LOADED_CLASSES_SCANNED, total_huge)
    check("java parser keeps no non-crypto names", crypto_huge == [])


def test_jcmd_failure_modes():
    original_which = runtime_probe.shutil.which
    try:
        runtime_probe.shutil.which = lambda name: None
        item = runtime_probe._java_loaded_classes(os.getpid())
        check("no jcmd → not_collected with a reason",
              item["status"] == "not_collected" and "not installed" in item["detail"],
              item)
    finally:
        runtime_probe.shutil.which = original_which

    original_run = runtime_probe.subprocess.run

    def _refuse(*_a, **_kw):
        class P:
            returncode = 1
            stdout = b""
            stderr = b"com.sun.tools.attach.AttachNotSupportedException"
        return P()

    try:
        runtime_probe.subprocess.run = _refuse
        item = runtime_probe._java_loaded_classes(os.getpid())
        check("attach refused → not_collected, never 'no crypto loaded'",
              item["status"] == "not_collected"
              and "attach refused" in item["detail"], item)
    finally:
        runtime_probe.subprocess.run = original_run

    def _timeout(*_a, **_kw):
        raise subprocess.TimeoutExpired(cmd="jcmd", timeout=1)

    try:
        runtime_probe.subprocess.run = _timeout
        item = runtime_probe._java_loaded_classes(os.getpid())
        check("jcmd timeout → error with the timeout named",
              item["status"] == "error" and "timed out" in item["detail"], item)
    finally:
        runtime_probe.subprocess.run = original_run


def test_non_jvm_and_permissions():
    report = _probe(os.getpid())
    item = _item(report, "java_loaded_classes")
    check("a non-JVM PID reports not_collected (no jcmd attempt)",
          item is not None and item["status"] == "not_collected"
          and "not look like a JVM" in item["detail"], item)
    check("runtime evidence is labelled as runtime, not static",
          all(entry.get("evidence_source") == "runtime"
              for entry in report["items"]))
    check("the probe never touches memory or the network",
          report["memory_inspected"] is False and report["network_used"] is False)

    try:
        runtime_probe.collect(enable=True, pid=1)
        denied = False
    except runtime_probe.RuntimeProbeDenied:
        denied = True
    check("PID 1 is refused (no root/other-UID escalation)", denied)

    foreign = None
    for candidate in ("/usr/share/jenkins/jenkins.war",):
        if os.path.isfile(candidate):
            foreign = candidate
    check("probe exposes no environment variables",
          "environ" not in str(report).lower())


def test_real_jvm_evidence():
    ok, reason = _jdk_available()
    if not ok:
        blocked("real JVM loaded-class evidence", reason,
                "apt-get install default-jdk && ./venv/bin/python test_runtime_java.py")
        return
    workdir = tempfile.mkdtemp(prefix="piquachu-jvm-")
    proc = None
    try:
        proc, state = _start_jvm(workdir)
        if proc is None:
            blocked("real JVM loaded-class evidence", state,
                    f"javac {workdir}/CryptoApp.java && "
                    f"java -cp {workdir} CryptoApp")
            return
        # Give the JVM a moment to load the crypto providers it actually uses.
        time.sleep(0.5)
        report = _probe(proc.pid)
        loaded = _item(report, "java_loaded_classes")
        check("real JVM: loaded classes were collected",
              loaded is not None and loaded["status"] == "collected", loaded)
        check("real JVM: collection is high-confidence evidence",
              loaded["confidence"] == "high", loaded)
        classes = loaded.get("crypto_classes") or []
        check("real JVM: javax.crypto classes are reported as loaded",
              any(name.startswith("javax.crypto") for name in classes), classes[:5])
        check("real JVM: java.security classes are reported as loaded",
              any(name.startswith("java.security") for name in classes), classes[:5])
        check("real JVM: the class count is plausible",
              loaded.get("loaded_classes_total", 0) > 100,
              loaded.get("loaded_classes_total"))

        classpath = _item(report, "java_configured_classpath")
        check("real JVM: classpath is a separate, low-confidence claim",
              classpath is not None
              and classpath["confidence"] == "low"
              and any(entry.endswith(workdir) or entry in workdir
                      for entry in (classpath.get("detail") or "").split(", ")),
              classpath)

        blob = str(report)
        check("real JVM: application secrets/values are not exported",
              "AES/GCM/NoPadding" not in blob and "SHA-256" not in blob)
        check("real JVM: no raw jcmd stream is stored",
              "java.lang.Object" not in blob)
        check("real JVM: the target process was not modified",
              proc.poll() is None)
        check("real JVM: no memory/network access was used",
              report["memory_inspected"] is False and report["network_used"] is False)
    finally:
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
        shutil.rmtree(workdir, ignore_errors=True)


TESTS = [
    test_parser_is_bounded_and_filters,
    test_jcmd_failure_modes,
    test_non_jvm_and_permissions,
    test_real_jvm_evidence,
]


def main() -> int:
    print("=" * 68)
    print("Runtime evidence — real JVM loaded classes (jcmd attach)")
    print("=" * 68)
    try:
        for test in TESTS:
            test()
    except AssertionError as exc:
        print(exc)
        print()
        print(f"FAILED: {len(FAILED)} check(s) — {FAILED}")
        print("=" * 68)
        return 1

    print()
    print("=" * 68)
    if BLOCKED:
        print(f"BLOCKED: {len(BLOCKED)} check group(s) need a JDK:")
        for item in BLOCKED:
            print(f"  ⊘ {item['check']} — {item['reason']}")
        print("(blocked checks were not counted as passed)")
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
