# backend/patcher.py
"""
patcher.py — guarded remediation patch generator (Phase 3 redesign)
===================================================================
Generates *surgical* rewrites (byte/char-offset edits — never ast.unparse
reformatting) and classifies every transformation before it can touch disk.

Applicability matrix (published in docs/engineering/phase-3-report.md):

  Rewrite                                  Class                   Preconditions
  ---------------------------------------  ----------------------  ---------------------------------------------
  hashlib.md5/sha1 -> sha256 (py)          conditional candidate   digest output not persisted/interchanged
  hashlib.new("md5"/"sha1") -> sha256      conditional candidate   same (identifiers, protocols, checksums)
  MessageDigest.getInstance weak (java)    conditional candidate   same
  Signature MD5withRSA->SHA256withRSA       conditional candidate   verifier interop; keeps RSA — NOT PQC
  random.randbytes(n) -> secrets.          safe mechanical         crypto use site (secret-named var),
    token_bytes(n) (non-test files)                                  same type+length semantics
  new Random(..) -> java.security.         safe mechanical         only when the type resolves to
    SecureRandom (non-test files)                                    java.util.Random (import-verified)
  other random.* on secret vars (py)       conditional candidate   type/length may change — review the diff
  AES/DES ECB -> GCM (py + java)           manual-only             nonce/tag/decrypt-compat not modeled
  DES/3DES -> AES/GCM (java)               manual-only             key material incompatible (56/112-bit)
  RSA/ECC -> ML-KEM/ML-DSA/SLH-DSA         manual-only             structured migration task, needs context
  static salt / protocol changes           manual-only             data-format dependent

Safety contract
---------------
* default is **dry-run** — unified diff only; ``apply`` needs ``--apply``;
* every path is validated against the target root (traversal, symlink escape,
  non-regular files, unsupported types are refused);
* writes are atomic (same-directory temp + fsync + os.replace), permissions
  and newlines are preserved, originals are backed up with a rollback
  manifest;
* files modified between diff and apply abort the whole batch (all-or-nothing
  staging) — nothing is partially applied;
* every rewritten file must re-parse (ast / javalang); if it does not, the
  edit is dropped. Unparseable files are refused with a reason — parse errors
  are NEVER "fixed" with regex edits;
* idempotence: a second run over patched output produces no further diff;
* GitHub PR creation is opt-in, previewed, scope-checked and confirmed —
  the default path performs no network I/O.
"""

from __future__ import annotations

import ast
import base64
import datetime as _dt
import difflib
import hashlib
import os
import re
import stat
import tempfile

try:
    import javalang
except Exception:  # optional dependency — Java patching degrades gracefully
    javalang = None

JAVALANG_AVAILABLE = javalang is not None

# Transformation classes ------------------------------------------------------
CLASS_SAFE = "safe-mechanical"
CLASS_CANDIDATE = "conditional-candidate"
CLASS_MANUAL = "manual-only"

SUPPORTED_EXTENSIONS = (".py", ".java")

# Directories never walked when patching a tree.
SKIP_DIRS = {"venv", ".venv", "node_modules", ".git", "dist", "build",
             "__pycache__", "site-packages", "target", ".piquachu-backups",
             ".piquachu-patches", ".idea", ".pytest_cache"}

SECRET_VAR_RE = re.compile(
    r"(^|[_\W])(key|secret|password|passwd|pwd|token|nonce|salt|iv|seed)([_\W]|$)",
    re.IGNORECASE,
)

# hashlib attribute -> replacement digest (all *candidates*: a digest swap is
# only safe when nothing persists/interchanges the exact output).
_HASH_REPLACEMENTS = {"md5": "sha256", "sha1": "sha256", "md4": "sha256"}
_WEAK_HASH_NEW = {"md5", "sha1", "md4"}

_RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices", "sample",
                 "uniform", "seed", "getrandbits", "randbytes"}

# Cheap text hints used *only* to decide whether an unparseable file deserves a
# refusal note. They never drive an edit.
_PY_HINT_RE = re.compile(r"hashlib|md5|sha1|MODE_ECB|from Crypto|import random")
_JAVA_HINT_RE = re.compile(r"getInstance|MessageDigest|new\s+Random|ECB|withRSA")


class PatchError(Exception):
    """A patch operation was refused (validation, conflict, policy)."""


class PatchConflictError(PatchError):
    """A target file changed between diff and apply — nothing was written."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _call_parts(node: ast.Call) -> list[str]:
    parts = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return list(reversed(parts))


def _is_random_call(node: ast.Call) -> bool:
    parts = _call_parts(node)
    return len(parts) == 2 and parts[0] == "random" and parts[1] in _RANDOM_FUNCS


def is_test_path(rel_path: str) -> bool:
    """Deterministic-test guard: crypto RNG rewrites never touch test sources."""
    parts = str(rel_path or "").replace("\\", "/").lower().split("/")
    base = parts[-1]
    if base in {"conftest.py"}:
        return True
    if base.startswith("test_") or base.endswith("_test.py"):
        return True
    if base.endswith("test.java") or base.endswith("tests.java"):
        return True
    return any(seg in {"test", "tests", "src/test"} for seg in parts[:-1])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rel_path(path: str, root: str | None) -> str:
    if root:
        try:
            rel = os.path.relpath(path, root)
        except ValueError:
            rel = path
    else:
        rel = path
    return rel.replace(os.sep, "/")


def _line_byte_offsets(src_bytes: bytes) -> list[int]:
    """Byte offset of the start of every line (AST col_offsets are UTF-8 bytes)."""
    starts = [0]
    idx = src_bytes.find(b"\n")
    while idx != -1:
        starts.append(idx + 1)
        idx = src_bytes.find(b"\n", idx + 1)
    starts.append(len(src_bytes) + 1)
    return starts


def _char_line_offsets(source: str) -> list[int]:
    """Character offset of the start of every line (javalang uses char columns)."""
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    offsets.append(len(source) + 1)
    return offsets


def _apply_edit_set(source: str, edits: list) -> tuple[str, list, list]:
    """Apply (start, end, new_text, meta) char-offset edits with containment
    protection: an edit fully inside a kept edit is dropped, never spliced
    twice. Returns (new_source, applied_meta, skipped_meta)."""
    ordered = sorted(edits, key=lambda e: (e[0], -e[1]))
    kept, skipped, last_end = [], [], -1
    for start, end, text, meta in ordered:
        if start < last_end:
            skipped.append(dict(meta, note="covered by an enclosing edit"))
            continue
        kept.append((start, end, text, meta))
        last_end = end
    out, cursor = [], 0
    for start, end, text, _meta in kept:
        out.append(source[cursor:start])
        out.append(text)
        cursor = end
    out.append(source[cursor:])
    return "".join(out), [k[3] for k in kept], skipped


def _crypto_hint(language: str, text: str) -> bool:
    pat = _PY_HINT_RE if language == "python" else _JAVA_HINT_RE
    return bool(pat.search(text))


def _add_missing_import(source: str, module: str) -> str:
    """Insert `import <module>` after the last top-level import; if there is
    none, after any leading comment/shebang block (license headers stay on
    top). Skipped when the module is already imported."""
    if re.search(rf"^\s*import {module}(\s|$)", source, re.M) or \
            re.search(rf"^\s*from {module} import", source, re.M):
        return source
    lines = source.splitlines()
    insert_at, seen_code = 0, False
    for i, line in enumerate(lines):
        if line.startswith(("import ", "from ")) and not line.startswith("from __future__"):
            insert_at = i + 1
            seen_code = True
        elif seen_code:
            break
    if not seen_code:
        insert_at = 0
        while insert_at < len(lines) and (
                lines[insert_at].startswith("#") or not lines[insert_at].strip()):
            insert_at += 1
    lines.insert(insert_at, f"import {module}")
    return "\n".join(lines) + ("\n" if source.endswith("\n") else "")


# ---------------------------------------------------------------------------
# Python surgical analyzer (byte-offset edits on UTF-8 source)
# ---------------------------------------------------------------------------

def analyze_python_source(source: str, *, include_candidates: bool = False,
                           is_test: bool = False) -> dict:
    """Classify + rewrite Python source surgically.

    Returns a dict with status (ok | parse-error), new_source and the
    transformation lists: applied / candidates / manual / skipped / notes.
    Only `safe-mechanical` edits are applied by default; `conditional-candidate`
    edits require include_candidates=True; `manual-only` is never edited.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {
            "status": "parse-error",
            "new_source": source,
            "changed": False,
            "applied": [], "candidates": [], "manual": [], "skipped": [],
            "notes": [
                f"Python source does not parse (SyntaxError at line "
                f"{exc.lineno}) — refusing to rewrite: parse errors are never "
                f"fixed with heuristic regex edits."],
        }

    src_bytes = source.encode("utf-8")
    starts = _line_byte_offsets(src_bytes)

    def off(lineno: int, col: int) -> int:
        return starts[lineno - 1] + col

    def btext(start: int, end: int) -> str:
        return src_bytes[start:end].decode("utf-8", errors="replace")

    edits: list = []          # (start, end, new_text, meta)
    manual: list = []         # manual-only records (no edit ever)
    skipped: list = []        # refused/inapplicable records

    def edit(span_start, span_end, text, meta):
        edits.append((span_start, span_end, text, meta))

    for node in ast.walk(tree):
        # hashlib.<weak> — attribute replacement (covers calls AND bare
        # references such as hmac.new(k, hashlib.md5)).
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id == "hashlib" and node.attr in _HASH_REPLACEMENTS:
            old = node.attr
            end = off(node.end_lineno, node.end_col_offset)
            start = end - len(old.encode("utf-8"))
            edit(start, end, _HASH_REPLACEMENTS[old], {
                "line": node.lineno,
                "what": f"hashlib.{old} → hashlib.{_HASH_REPLACEMENTS[old]}",
                "class": CLASS_CANDIDATE,
                "detail": ("Weak digest swap (FIPS 180-4 SHA-256). Applied only "
                           "as a reviewed candidate."),
                "preconditions": [
                    "the digest output is not persisted or exchanged "
                    "(DB columns, checksums, tokens, protocol fields)",
                    "no interoperability depends on the exact digest value "
                    "(HMAC tags, signature payloads, cache keys)",
                ],
            })

        # hashlib.new("md5" | "sha1" | "md4")
        if isinstance(node, ast.Call):
            parts = _call_parts(node)
            if len(parts) == 2 and parts[0] == "hashlib" and parts[1] == "new" \
                    and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str) \
                    and node.args[0].value.lower() in _WEAK_HASH_NEW:
                arg = node.args[0]
                old = arg.value
                start = off(arg.lineno, arg.col_offset)
                end = off(arg.end_lineno, arg.end_col_offset)
                edit(start, end, '\"sha256\"', {
                    "line": node.lineno,
                    "what": f"hashlib.new({old!r}) → hashlib.new('sha256')",
                    "class": CLASS_CANDIDATE,
                    "detail": ("Weak digest swap (FIPS 180-4 SHA-256). Applied "
                               "only as a reviewed candidate."),
                    "preconditions": [
                        "the digest output is not persisted or exchanged",
                        "no interop depends on the exact digest value",
                    ],
                })

        # ECB / DES mode constructors: manual-only (never edited). The
        # receiver check works for `AES.new(...)` and `Crypto.Cipher.AES.new(...)`.
        if isinstance(node, ast.Call):
            parts = _call_parts(node)
            if len(parts) >= 2 and parts[-1] == "new" \
                    and parts[-2] in ("AES", "DES", "DES3", "des", "des3"):
                ecb = any(isinstance(a, ast.Attribute) and a.attr == "MODE_ECB"
                          or isinstance(a, ast.Constant) and isinstance(a.value, str)
                          and a.value.upper() == "ECB"
                          for a in node.args)
                if ecb:
                    manual.append({
                        "line": node.lineno,
                        "what": f"{parts[-2]}.new(..., ECB) → AES-GCM migration",
                        "class": CLASS_MANUAL,
                        "detail": (
                            "AES/ECB → AES/GCM is deliberately NOT rewritten: GCM "
                            "requires a fresh 12-byte nonce per message, authenticated "
                            "tag storage and verification, and a decryption-"
                            "compatibility review. A mode-string swap would silently "
                            "break every existing ciphertext."),
                        "follow_up": [
                            "generate/record a unique 12-byte nonce per message",
                            "persist and verify the 16-byte GCM tag on decrypt",
                            "re-encrypt or migrate existing ECB ciphertexts",
                            "run `cipher_cli.py remediate` for the full plan",
                        ],
                    })

    # Secret-keyed RNG rewrites (assignment targets only — crypto use sites).
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        targets = [t for t in targets if SECRET_VAR_RE.search(t)]
        if not targets or not (isinstance(node.value, ast.Call)
                               and _is_random_call(node.value)):
            continue
        call = node.value
        parts = _call_parts(call)
        line = call.lineno
        if is_test:
            skipped.append({
                "line": line,
                "what": f"{parts[0]}.{parts[1]} → secrets (not applied)",
                "class": CLASS_CANDIDATE,
                "note": ("test path — RNG rewrites are never applied to test "
                         "sources so seeded/deterministic tests keep working"),
            })
            continue
        span_start = off(call.lineno, call.col_offset)
        span_end = off(call.end_lineno, call.end_col_offset)
        if parts[1] == "randbytes" and call.args:
            arg = call.args[0]
            arg_text = btext(off(arg.lineno, arg.col_offset),
                             off(arg.end_lineno, arg.end_col_offset))
            replacement = f"secrets.token_bytes({arg_text})"
            meta = {
                "line": line,
                "what": f"{targets[0]} = secrets.token_bytes({arg_text})",
                "class": CLASS_SAFE,
                "detail": ("random.randbytes → secrets.token_bytes: CSPRNG for "
                           "cryptographic material with identical type and length "
                           "semantics (non-test crypto use site)."),
                "needs_import": True,
            }
        else:
            replacement = "secrets.token_bytes(32)"
            meta = {
                "line": line,
                "what": f"{targets[0]} = secrets.token_bytes(32)  # from random.{parts[1]}",
                "class": CLASS_CANDIDATE,
                "detail": ("Insecure random → secrets for a secret-named variable. "
                           "CANDIDATE: the replacement always yields 32 bytes — "
                           "verify the original value's type and length expectations "
                           "before applying."),
                "preconditions": [
                    "the value is cryptographic key/nonce/salt material",
                    "type and length changes (if any) are acceptable",
                    "the file is not a deterministic (seeded) test fixture",
                ],
                "needs_import": True,
            }
        edit(span_start, span_end, replacement, meta)

    if not edits:
        return {"status": "ok", "new_source": source, "changed": False,
                "applied": [], "candidates": [], "manual": manual,
                "skipped": skipped, "notes": []}

    return _finalize_python(source, edits, manual, skipped,
                            include_candidates=include_candidates)


def _finalize_python(source, edits, manual, skipped, *, include_candidates) -> dict:
    """Select the edit variant (all vs safe-only), insert imports and validate
    by re-parsing. If no variant validates, nothing is applied."""
    notes = []
    variants = []
    if include_candidates:
        variants.append(list(edits))
    safe_only = [e for e in edits if e[3].get("class") != CLASS_CANDIDATE]
    if len(safe_only) != len(edits):
        variants.append(safe_only)
    if not variants:
        variants.append(list(edits))

    all_candidate_metas = [e[3] for e in edits
                           if e[3].get("class") == CLASS_CANDIDATE]
    for idx, variant in enumerate(variants):
        new_src, kept, inner_skipped = _apply_edit_set(source, variant)
        if any(m.get("needs_import") for m in kept):
            new_src = _add_missing_import(new_src, "secrets")
        try:
            ast.parse(new_src)
        except SyntaxError as exc:
            notes.append(f"variant {idx + 1} failed re-parse "
                         f"(SyntaxError line {exc.lineno}) — trying a more "
                         f"conservative edit set")
            skipped.extend(dict(m, note="dropped: variant failed validation")
                           for m in kept)
            continue
        applied = kept
        applied_ids = {id(m) for m in applied}
        candidates = ([dict(m) for m in all_candidate_metas
                       if id(m) not in applied_ids]
                      + [dict(m, note="covered by an enclosing edit")
                         for m in inner_skipped
                         if m.get("class") == CLASS_CANDIDATE])
        if include_candidates and variant is variants[0]:
            candidates = [dict(m, note="covered by an enclosing edit")
                          for m in inner_skipped
                          if m.get("class") == CLASS_CANDIDATE]
        return {"status": "ok", "new_source": new_src,
                "changed": new_src != source,
                "applied": applied, "candidates": candidates,
                "manual": manual, "skipped": skipped + inner_skipped,
                "notes": notes}
    return {"status": "ok", "new_source": source, "changed": False,
            "applied": [], "candidates": [], "manual": manual,
            "skipped": skipped,
            "notes": notes + ["post-edit validation failed — no changes applied"]}


# ---------------------------------------------------------------------------
# Java surgical analyzer (javalang, char-offset edits)
# ---------------------------------------------------------------------------

def _java_creator_type_name(node) -> str | None:
    """Flatten a javalang ClassCreator type (str | ReferenceType chain | list)
    to a dotted/ simple name."""
    t = getattr(node, "type", None)
    if isinstance(t, str):
        return t
    if isinstance(t, list):
        return ".".join(str(x) for x in t)
    names = []
    cur = t
    while cur is not None:
        name = getattr(cur, "name", None)
        if not isinstance(name, str):
            return None
        names.append(name)
        cur = getattr(cur, "sub_type", None)
    return ".".join(names) if names else None

def _java_random_allowed(tree) -> tuple[bool, str]:
    """Guard: only rewrite `new Random(` when the type provably resolves to
    java.util.Random (explicit import or qualified use). Wildcard imports or a
    conflicting `Random` import mean a project-local class could be meant —
    refuse instead of guessing."""
    explicit_ok = False
    qualified_ok = False
    conflicting = []
    for _, node in tree:
        # javalang 0.13 calls it `Import`; older builds `ImportDeclaration`.
        if type(node).__name__ in ("Import", "ImportDeclaration"):
            if bool(getattr(node, "static", False)):
                continue  # static imports do not bind a type name here
            path = str(getattr(node, "path", "") or "")
            wildcard = bool(getattr(node, "wildcard", False))
            if wildcard:
                if path in ("java.util", "java"):
                    explicit_ok = True          # binds java.util.Random
                elif not path:
                    conflicting.append(".*")
                else:
                    conflicting.append(path + ".*")  # could bind another Random
            else:
                if path == "java.util.Random":
                    explicit_ok = True
                elif path.endswith(".Random"):
                    conflicting.append(path)    # a *different* Random class
        if type(node).__name__ == "ClassCreator":
            full = _java_creator_type_name(node) or ""
            if full == "java.util.Random":
                qualified_ok = True
            elif full == "Random":
                pass  # needs an import decision below
            elif full.endswith(".Random") and full != "java.util.Random":
                conflicting.append(full)
    if conflicting:
        return False, ("Random type resolution is ambiguous ("
                       + ", ".join(sorted(set(conflicting))[:4])
                       + ") — refusing to rewrite a possibly project-local class")
    if qualified_ok or explicit_ok:
        return True, ""
    return False, ("unqualified `new Random(` without a java.util.Random import "
                   "— could be a project-local class; refusing")


def analyze_java_source(source: str, *, include_candidates: bool = False,
                        is_test: bool = False) -> dict:
    """Classify + rewrite Java source surgically via the javalang AST.

    With javalang unavailable the source is returned untouched with
    status="unavailable" — Java is never regex-guessed.
    """
    if not JAVALANG_AVAILABLE:
        return {"status": "unavailable", "new_source": source, "changed": False,
                "applied": [], "candidates": [], "manual": [], "skipped": [],
                "notes": ["javalang not installed — Java rewrites are skipped "
                          "(never guessed with regexes)."]}
    try:
        tree = javalang.parse.parse(source)
    except javalang.parser.JavaSyntaxError as exc:
        return {"status": "parse-error", "new_source": source, "changed": False,
                "applied": [], "candidates": [], "manual": [], "skipped": [],
                "notes": [f"Java source does not parse ({exc}) — refusing to "
                          f"rewrite: parse errors are never fixed with heuristic "
                          f"regex edits."]}
    except Exception as exc:  # tokenizer failures etc.
        return {"status": "parse-error", "new_source": source, "changed": False,
                "applied": [], "candidates": [], "manual": [], "skipped": [],
                "notes": [f"Java parse failed ({type(exc).__name__}: {exc}) — "
                          f"refusing to rewrite."]}

    offsets = _char_line_offsets(source)

    def off(position) -> int:
        return offsets[position.line - 1] + (position.column - 1)

    edits: list = []
    manual: list = []
    skipped: list = []

    _JAVA_WEAK_DIGESTS = {"MD5", "MD2", "SHA", "SHA-1", "SHA1"}
    _JAVA_WEAK_SIGNATURES = {"MD5withRSA", "MD2withRSA", "SHA1withRSA", "SHAwithRSA"}
    _JAVA_ECB_RE = re.compile(r"^\s*AES\s*/\s*ECB\s*/", re.IGNORECASE)
    _JAVA_DES_RE = re.compile(r"^\s*(DES|DESede|3DES)(\s*/.*)?$", re.IGNORECASE)

    for _path, node in tree:
        if type(node).__name__ != "MethodInvocation" or node.member != "getInstance":
            continue
        qualifier = str(getattr(node, "qualifier", "") or "").split(".")[-1]
        arg = node.arguments[0] if node.arguments else None
        value = getattr(arg, "value", None) if arg is not None else None
        pos = getattr(arg, "position", None) if arg is not None else None
        if pos is None or not isinstance(value, str) or not value.startswith('\"'):
            continue
        literal = value[1:-1]
        start, end = off(pos), off(pos) + len(value)
        line = pos.line

        if qualifier == "MessageDigest" and literal.upper() in _JAVA_WEAK_DIGESTS:
            edits.append((start, end, '\"SHA-256\"', {
                "line": line,
                "what": f"MessageDigest {literal} → SHA-256",
                "class": CLASS_CANDIDATE,
                "detail": ("Digest swap (FIPS 180-4 SHA-256), applied only as a "
                           "reviewed candidate."),
                "preconditions": [
                    "digest output not persisted/exchanged (fingerprints, "
                    "integrity files, protocol fields)",
                    "no interop depends on the exact digest",
                ],
            }))
        elif qualifier == "Cipher" and _JAVA_ECB_RE.match(literal):
            manual.append({
                "line": line,
                "what": f"Cipher {literal} → AES/GCM migration",
                "class": CLASS_MANUAL,
                "detail": (
                    "ECB→GCM is deliberately NOT rewritten: GCM needs a fresh "
                    "12-byte nonce (GCMParameterSpec), 16-byte tag storage and "
                    "verification, and a decryption-compatibility review — a "
                    "literal swap would break every existing ciphertext."),
                "follow_up": [
                    "supply a unique 12-byte nonce per encryption via GCMParameterSpec",
                    "persist and verify the GCM tag on decrypt",
                    "re-encrypt existing ECB ciphertexts",
                    "run `cipher_cli.py remediate` for the full plan",
                ],
            })
        elif qualifier == "Cipher" and _JAVA_DES_RE.match(literal):
            manual.append({
                "line": line,
                "what": f"Cipher {literal} → AES/GCM migration (manual)",
                "class": CLASS_MANUAL,
                "detail": (
                    "DES/3DES → AES is deliberately NOT rewritten: DES keys are "
                    "56-bit (8 bytes) and 3DES 112/168-bit — AES needs "
                    "16/24/32-byte keys, so key material must be regenerated as "
                    "part of a migration, not a text substitution."),
                "follow_up": [
                    "generate new AES-256 key material (DES keys are incompatible)",
                    "supply a unique 12-byte nonce per encryption",
                    "plan ciphertext re-encryption / key rotation",
                    "run `cipher_cli.py remediate` for the full plan",
                ],
            })
        elif qualifier == "Signature" and literal in _JAVA_WEAK_SIGNATURES:
            edits.append((start, end, '\"SHA256withRSA\"', {
                "line": line,
                "what": f"Signature {literal} → SHA256withRSA",
                "class": CLASS_CANDIDATE,
                "detail": (
                    "Legacy DIGEST remediation while keeping RSA — this is NOT "
                    "a PQC migration (ML-DSA would need a new key type, wire "
                    "format and verifier). Applied only as a reviewed candidate."),
                "preconditions": [
                    "every verifier accepts SHA256withRSA signatures",
                    "existing SHA1 signatures are re-signed or grandfathered",
                ],
                "follow_up": [
                    "PQC signature migration (ML-DSA) is a separate, structured "
                    "task — see the remediation plan",
                ],
            }))

    # `new Random(...)` / `new java.util.Random(...)` — AST-count-verified.
    random_creators = [n for _p, n in tree
                       if type(n).__name__ == "ClassCreator"
                       and (_java_creator_type_name(n) or "") in ("Random", "java.util.Random")]
    if random_creators:
        if is_test:
            skipped.append({"line": 0,
                            "what": f"new Random → SecureRandom ({len(random_creators)} site(s))",
                            "class": CLASS_SAFE,
                            "note": "test path — RNG rewrites are never applied "
                                    "to test sources"})
        else:
            allowed, why = _java_random_allowed(tree)
            if not allowed:
                skipped.append({"line": 0, "what": "new Random → SecureRandom",
                                "class": CLASS_SAFE, "note": why})
            else:
                matches = list(re.finditer(r"new\s+(?:java\.util\.)?Random\s*\x28",
                                           source))
                if len(matches) != len(random_creators):
                    skipped.append({
                        "line": 0, "what": "new Random → SecureRandom",
                        "class": CLASS_SAFE,
                        "note": (f"{len(matches)} textual `new Random(` site(s) "
                                 f"vs {len(random_creators)} parsed AST "
                                 f"constructor(s) — possibly in comments; "
                                 f"refusing a non-1:1 match")})
                else:
                    for m in matches:
                        edits.append((m.start(), m.end(),
                                      "new java.security.SecureRandom(", {
                                          "line": source.count("\n", 0, m.start()) + 1,
                                          "what": (m.group(0) +
                                                   " → new java.security.SecureRandom("),
                                          "class": CLASS_SAFE,
                                          "detail": ("java.util.Random → "
                                                     "SecureRandom (CSPRNG); "
                                                     "API-compatible subclass."),
                                      }))

    if not edits:
        return {"status": "ok", "new_source": source, "changed": False,
                "applied": [], "candidates": [], "manual": manual,
                "skipped": skipped, "notes": []}

    notes = []
    variants = []
    if include_candidates:
        variants.append(list(edits))
    safe_only = [e for e in edits if e[3].get("class") != CLASS_CANDIDATE]
    if len(safe_only) != len(edits):
        variants.append(safe_only)
    if not variants:
        variants.append(list(edits))

    all_candidate_metas = [e[3] for e in edits
                           if e[3].get("class") == CLASS_CANDIDATE]
    for idx, variant in enumerate(variants):
        new_src, kept, inner_skipped = _apply_edit_set(source, variant)
        try:
            javalang.parse.parse(new_src)
        except Exception as exc:
            notes.append(f"variant {idx + 1} failed Java re-parse "
                         f"({type(exc).__name__}) — trying a more conservative "
                         f"edit set")
            skipped.extend(dict(m, note="dropped: variant failed validation")
                           for m in kept)
            continue
        applied_ids = {id(m) for m in kept}
        skipped_ids = {id(m) for m in inner_skipped}
        candidates = [dict(m) for m in all_candidate_metas
                      if id(m) not in applied_ids and id(m) not in skipped_ids]
        candidates += [dict(m, note="covered by an enclosing edit")
                       for m in inner_skipped
                       if m.get("class") == CLASS_CANDIDATE
                       and id(m) not in applied_ids]
        if include_candidates and idx == 0:
            candidates = [dict(m, note="covered by an enclosing edit")
                          for m in inner_skipped
                          if m.get("class") == CLASS_CANDIDATE]
        return {"status": "ok", "new_source": new_src,
                "changed": new_src != source,
                "applied": kept, "candidates": candidates,
                "manual": manual, "skipped": skipped + inner_skipped,
                "notes": notes}
    return {"status": "ok", "new_source": source, "changed": False,
            "applied": [], "candidates": [], "manual": manual,
            "skipped": skipped,
            "notes": notes + ["post-edit validation failed — no changes applied"]}


# ---------------------------------------------------------------------------
# Public analyze/rewrite API (backward-compatible wrappers)
# ---------------------------------------------------------------------------

def analyze_source(source: str, language: str, *, include_candidates: bool = False,
                   is_test: bool = False) -> dict:
    if language == "java":
        return analyze_java_source(source, include_candidates=include_candidates,
                                   is_test=is_test)
    return analyze_python_source(source, include_candidates=include_candidates,
                                 is_test=is_test)


def rewrite_python_source(source: str, *, include_candidates: bool = False,
                          is_test: bool = False) -> tuple[str, list]:
    """Apply *safe* rewrites (plus candidates when include_candidates=True).
    Returns (new_source, applied_changes). Manual-only items are never edited."""
    res = analyze_python_source(source, include_candidates=include_candidates,
                                is_test=is_test)
    return res["new_source"], res["applied"]


def rewrite_java_source(source: str, *, include_candidates: bool = False,
                        is_test: bool = False) -> tuple[str, list]:
    res = analyze_java_source(source, include_candidates=include_candidates,
                              is_test=is_test)
    return res["new_source"], res["applied"]


# ---------------------------------------------------------------------------
# build_patch — one file -> patch record (diff + full metadata)
# ---------------------------------------------------------------------------

def _rules_for(findings, rel: str, line) -> list[str]:
    if not findings or line is None:
        return []
    rules = []
    for f in findings:
        if str(f.get("file") or "").replace("\\", "/") != rel:
            continue
        fline = f.get("line") or f.get("line_start")
        f_end = f.get("line_end") or fline
        try:
            if int(fline) - 1 <= int(line) <= int(f_end) + 1:
                rules.append(str(f.get("rule_id") or f.get("vulnerability") or ""))
        except (TypeError, ValueError):
            continue
    return sorted({r for r in rules if r})


def _refusal(path: str, root: str | None, applicability: str, reason: str,
             *, language: str, findings=None, old_sha256=None) -> dict:
    rel = _rel_path(path, root)
    rules = sorted({str(f.get("rule_id") or f.get("vulnerability") or "")
                    for f in (findings or [])
                    if str(f.get("file") or "").replace("\\", "/") == rel}
                   - {""})
    return {
        "path": rel, "abs_path": os.path.abspath(path),
        "root": os.path.abspath(root) if root else None,
        "language": language, "applicability": applicability,
        "reason": reason, "diff": "",
        "changes": [], "candidates": [], "manual": [], "skipped": [],
        "notes": [reason],
        "rule_ids": rules,
        "old_sha256": old_sha256, "new_sha256": old_sha256,
        "validation": {"command": None, "ok": None},
        "confidence": "n/a", "follow_up": [reason],
        "original": None, "new_content": None,
    }


def build_patch(path: str, root: str | None = None, *,
                include_candidates: bool = False,
                findings: list | None = None) -> dict | None:
    """Build a patch record for one file (dry-run data only — never writes).

    Returns None when the file has nothing to report. Refusals (parse errors,
    symlinks, non-regular files, missing analyzer) come back as records with an
    `applicability` explaining exactly why nothing will be rewritten.
    """
    ext = os.path.splitext(path)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return None
    language = "python" if ext == ".py" else "java"
    rel = _rel_path(path, root)

    if os.path.islink(path):
        return _refusal(path, root, "refused-symlink",
                        f"{rel} is a symlink — symlinked files are never "
                        f"rewritten (target could escape the scan root)",
                        language=language, findings=findings)
    try:
        st = os.lstat(path)
    except OSError as exc:
        return _refusal(path, root, "refused-not-regular",
                        f"cannot stat {rel}: {exc}", language=language,
                        findings=findings)
    if not stat.S_ISREG(st.st_mode):
        return _refusal(path, root, "refused-not-regular",
                        f"{rel} is not a regular file", language=language,
                        findings=findings)

    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return _refusal(path, root, "refused-not-regular",
                        f"cannot read {rel}: {exc}", language=language,
                        findings=findings)
    old_sha = _sha256(raw)
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        hint = _crypto_hint(language, raw.decode("latin-1"))
        if hint:
            return _refusal(path, root, "refused-non-utf8",
                            f"{rel} is not valid UTF-8 — refusing to rewrite so "
                            f"the original encoding is preserved",
                            language=language, findings=findings,
                            old_sha256=old_sha)
        return None

    is_test = is_test_path(rel)
    res = analyze_source(source, language, include_candidates=include_candidates,
                         is_test=is_test)

    if res["status"] == "parse-error":
        detail = "; ".join(res.get("notes") or ["parse failed"])
        if _crypto_hint(language, source) or (findings and any(
                str(f.get("file") or "").replace("\\", "/") == rel
                for f in findings)):
            return _refusal(path, root, "refused-parse-error",
                            f"{rel}: {detail}", language=language,
                            findings=findings, old_sha256=old_sha)
        return None
    if res["status"] == "unavailable":
        if _crypto_hint(language, source):
            return _refusal(path, root, "skipped-analyzer-unavailable",
                            f"{rel}: {'; '.join(res.get('notes') or [])}",
                            language=language, findings=findings,
                            old_sha256=old_sha)
        return None

    applied = res["applied"]
    candidates = res["candidates"]
    manual = res["manual"]
    skipped = res["skipped"]
    notes = res["notes"]
    if not (applied or candidates or manual or skipped or notes):
        return None

    new_source = res["new_source"]
    changed = bool(res["changed"]) and new_source != source
    diff = ""
    if changed:
        diff = "".join(difflib.unified_diff(
            source.splitlines(keepends=True),
            new_source.splitlines(keepends=True),
            fromfile=f"a/{rel}", tofile=f"b/{rel}"))

    if changed:
        applicability = "applied"
    elif candidates:
        applicability = "candidate-only"
    elif manual:
        applicability = "manual-only"
    else:
        applicability = "skipped"

    # Validation evidence: what was (or would be) proven by re-parsing.
    if changed:
        validation = {
            "command": ("python: ast.parse round-trip of patched source"
                        if language == "python"
                        else "java: javalang re-parse of patched source"),
            "ok": True,
        }
    elif candidates:
        check = analyze_source(source, language, include_candidates=True,
                               is_test=is_test)
        validation = {
            "command": ("python: ast.parse round-trip if candidates were applied"
                        if language == "python"
                        else "java: javalang re-parse if candidates were applied"),
            "ok": check["status"] == "ok" and check["changed"]
                   and check["new_source"] != source
                   and check["status"] == "ok",
            "detail": ("candidate set parses cleanly; semantic safety still "
                       "requires the documented preconditions"),
        }
        if check["status"] == "ok" and check["changed"]:
            try:
                if language == "python":
                    ast.parse(check["new_source"])
                elif JAVALANG_AVAILABLE:
                    javalang.parse.parse(check["new_source"])
                validation["ok"] = True
            except Exception as exc:
                validation["ok"] = False
                validation["detail"] = f"candidate variant failed: {exc}"
    else:
        validation = {"command": "n/a — no rewrite generated", "ok": None}

    if changed:
        classes = {c.get("class") for c in applied}
        confidence = "high" if classes <= {CLASS_SAFE} else "medium"
    else:
        confidence = "low"

    rule_ids = set()
    for entry in applied + candidates + manual:
        rule_ids.update(_rules_for(findings, rel, entry.get("line")))
    if not rule_ids and findings:
        rule_ids = {str(f.get("rule_id") or f.get("vulnerability") or "")
                    for f in findings
                    if str(f.get("file") or "").replace("\\", "/") == rel}
        rule_ids.discard("")

    follow_up = []
    for m in manual:
        follow_up.extend(m.get("follow_up") or [])
    for m in candidates:
        for pre in m.get("preconditions") or []:
            follow_up.append(f"candidate L{m.get('line')}: {pre}")
        follow_up.extend(m.get("follow_up") or [])
    follow_up.extend(notes)

    return {
        "path": rel,
        "abs_path": os.path.abspath(path),
        "root": os.path.abspath(root) if root else None,
        "language": language,
        "applicability": applicability,
        "diff": diff,
        "changes": applied,
        "candidates": candidates,
        "manual": manual,
        "skipped": skipped,
        "notes": notes,
        "rule_ids": sorted(rule_ids),
        "old_sha256": old_sha,
        "new_sha256": _sha256(new_source.encode("utf-8")) if changed else old_sha,
        "validation": validation,
        "confidence": confidence,
        "follow_up": follow_up,
        "original": source,
        "new_content": new_source if changed else None,
        "is_test_path": is_test,
    }


def patch_directory(target_directory: str, findings: list | None = None, *,
                    include_candidates: bool = False) -> list[dict]:
    """Build patch records for .py/.java files under target_directory.

    When `findings` is provided only scan-flagged files are analyzed and only
    non-compliant findings count (PASS evidence never triggers a patch).
    Symlinks and unsupported files are skipped before analysis.
    """
    patchable = None
    if findings:
        patchable = {
            os.path.normpath(os.path.join(target_directory, f.get("file", "")))
            for f in findings
            if (f.get("file", "").endswith(".py") or f.get("file", "").endswith(".java"))
            and not f.get("pqc_compliant")
        }

    patches = []
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS
                   and not os.path.islink(os.path.join(root, d))]
        for name in files:
            if not name.endswith(SUPPORTED_EXTENSIONS):
                continue
            path = os.path.join(root, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            if patchable is not None and os.path.normpath(path) not in patchable:
                continue
            patch = build_patch(path, root=target_directory,
                                include_candidates=include_candidates,
                                findings=findings)
            if patch:
                patches.append(patch)
    patches.sort(key=lambda p: p["path"])
    return patches


# ---------------------------------------------------------------------------
# Artifacts: unified diffs + manifest (dry-run default)
# ---------------------------------------------------------------------------

def write_patches(patches: list[dict], out_dir: str) -> list[str]:
    """Write one .diff per applicable patch plus `patch-manifest.json` with the
    full metadata (rule ids, hashes, validation, applicability, follow-ups).
    The manifest uses repository-relative paths only — safe as a CI artifact.
    Returns the written diff paths.
    """
    import json
    os.makedirs(out_dir, exist_ok=True)
    written = []
    manifest_entries = []
    for patch in patches:
        if patch.get("diff"):
            out = os.path.join(out_dir, patch["path"].replace("/", "__") + ".diff")
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(patch["diff"])
                fh.write("\n# PiQuaChu patch record:\n")
                for c in patch["changes"]:
                    fh.write(f"#   L{c['line']}: {c['what']} [{c.get('class', '?')}]\n")
                if patch.get("rule_ids"):
                    fh.write("#   rules: " + ", ".join(patch["rule_ids"]) + "\n")
            written.append(out)
        manifest_entries.append({
            "path": patch["path"],
            "language": patch.get("language"),
            "applicability": patch.get("applicability"),
            "rule_ids": patch.get("rule_ids", []),
            "old_sha256": patch.get("old_sha256"),
            "new_sha256": patch.get("new_sha256"),
            "changes": [{k: c.get(k) for k in ("line", "what", "class", "detail")}
                        for c in patch.get("changes", [])],
            "candidates": [{k: c.get(k) for k in ("line", "what", "class", "detail")}
                           for c in patch.get("candidates", [])],
            "manual": [{k: c.get(k) for k in ("line", "what", "class", "detail")}
                       for c in patch.get("manual", [])],
            "reason": patch.get("reason"),
            "validation": patch.get("validation"),
            "confidence": patch.get("confidence"),
            "follow_up": patch.get("follow_up", []),
            "rule_ids_note": (
                "finding/rule linkage is by file+line at scan time"),
        })
    manifest = {
        "kind": "piquachu-patch-manifest",
        "version": 1,
        "created_at": _dt.datetime.now(_dt.timezone.utc)
                      .replace(microsecond=0).isoformat(),
        "note": ("Repository-relative paths only; safe to publish as a CI "
                 "artifact. Applying changes requires `cipher_cli.py patch "
                 "--apply` on a local checkout."),
        "patches": manifest_entries,
    }
    manifest_path = os.path.join(out_dir, "patch-manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return written


# ---------------------------------------------------------------------------
# apply — all-or-nothing, atomic, backed up, conflict-checked
# ---------------------------------------------------------------------------

def _validate_patch_target(patch: dict, root: str) -> bytes:
    """Validate one patch target against the target root. Returns the current
    original bytes when safe; raises PatchError/PatchConflictError otherwise.
    Nothing in here writes to disk."""
    path = patch.get("abs_path") or ""
    rel = patch.get("path") or ""
    if not rel or rel.startswith("/") or ".." in rel.split("/"):
        raise PatchError(f"unsafe patch path {rel!r} (traversal)")
    root_real = os.path.realpath(root)
    if os.path.islink(path):
        raise PatchError(f"{rel}: refusing to patch a symlink")
    real = os.path.realpath(path)
    if real != root_real and not real.startswith(root_real + os.sep):
        raise PatchError(f"{rel}: resolves outside the target root "
                         f"(symlink or path traversal escape) — refusing")
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise PatchError(f"{rel}: cannot stat ({exc})") from exc
    if not stat.S_ISREG(st.st_mode):
        raise PatchError(f"{rel}: not a regular file")
    ext = os.path.splitext(path)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise PatchError(f"{rel}: unsupported file type {ext!r}")
    # Guard against a directory swapped for a symlink between checks.
    parent_real = os.path.realpath(os.path.dirname(path))
    if not (parent_real == root_real or parent_real.startswith(root_real + os.sep)):
        raise PatchError(f"{rel}: parent directory resolves outside the root")
    with open(path, "rb") as fh:
        raw = fh.read()
    expected = patch.get("old_sha256")
    if expected and _sha256(raw) != expected:
        raise PatchConflictError(
            f"{rel}: file changed since the diff was generated "
            f"(expected sha256 {expected[:12]}…, found "
            f"{_sha256(raw)[:12]}…) — re-run the scan; nothing was applied")
    if patch.get("original") is not None:
        try:
            if raw.decode("utf-8") != patch["original"]:
                raise PatchConflictError(
                    f"{rel}: content differs from the analyzed source — "
                    f"re-run the scan; nothing was applied")
        except UnicodeDecodeError as exc:
            raise PatchConflictError(
                f"{rel}: file is no longer valid UTF-8 — nothing was applied") from exc
    return raw


def _atomic_write(path: str, data: bytes) -> None:
    """Same-directory temp file + fsync + atomic replace; mode preserved."""
    directory = os.path.dirname(path) or "."
    mode = os.stat(path).st_mode & 0o7777
    fd, tmp = tempfile.mkstemp(prefix=".pqu-patch-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        try:
            dfd = os.open(directory, os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except (OSError, AttributeError):
            pass
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def apply_patches(patches: list[dict], *, root: str | None = None,
                  backup_dir: str | None = None) -> list[str]:
    """Apply applicable patches in place — ALL-OR-NOTHING.

    Phase 1 validates every target (root containment, symlink/regular-file/
    extension checks, content-hash conflict detection). Any failure aborts
    before a single byte is written. Phase 2 writes each file atomically with
    an original backup; a mid-batch failure restores already-written files.
    A rollback manifest (with hashes + backup locations) is written next to
    the backups. Returns the list of modified relative paths.
    """
    import json
    targets = [p for p in patches if p.get("diff") and p.get("new_content")]
    if not targets:
        return []

    # A refused/skipped record must never be written, even if a caller
    # re-populates its diff/new_content: the refusal is the decision.
    for patch in targets:
        applicability = str(patch.get("applicability") or "")
        if applicability and applicability != "applied":
            raise PatchError(
                f"{patch.get('path')}: record is '{applicability}', not "
                f"'applied' — refusing to write (re-run after fixing the "
                f"reported problem)")

    roots = {p.get("root") for p in targets if p.get("root")}
    if root:
        roots.add(os.path.abspath(root))
    if len(roots) > 1:
        raise PatchError(f"patches span multiple roots {sorted(roots)} — "
                         f"applying must target one directory")
    target_root = os.path.abspath(root or next(iter(roots))
                                  or os.path.dirname(targets[0]["abs_path"]))
    if not os.path.isdir(target_root):
        raise PatchError(f"target root is not a directory: {target_root}")

    originals: dict[str, bytes] = {}
    for patch in targets:
        if os.path.realpath(patch["abs_path"]).startswith(
                os.path.realpath(target_root) + os.sep) or \
                os.path.realpath(patch["abs_path"]) == os.path.realpath(target_root):
            pass
        else:
            raise PatchError(f"{patch.get('path')}: outside target root "
                             f"{target_root} — refusing")
        originals[patch["abs_path"]] = _validate_patch_target(patch, target_root)

    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = backup_dir or os.path.join(target_root,
                                             ".piquachu-backups", stamp)
    backup_root = os.path.abspath(backup_root)
    os.makedirs(backup_root, exist_ok=True)

    manifest_files = []
    written: list[str] = []
    try:
        for patch in targets:
            rel = patch["path"]
            backup_name = rel.replace("/", "__") + ".orig"
            backup_path = os.path.join(backup_root, backup_name)
            with open(backup_path, "wb") as fh:
                fh.write(originals[patch["abs_path"]])
                fh.flush()
                os.fsync(fh.fileno())
            new_bytes = patch["new_content"].encode("utf-8")
            _atomic_write(patch["abs_path"], new_bytes)
            written.append(rel)
            manifest_files.append({
                "path": rel,
                "old_sha256": patch.get("old_sha256"),
                "new_sha256": _sha256(new_bytes),
                "backup": backup_name,
                "rule_ids": patch.get("rule_ids", []),
                "classes": sorted({c.get("class") for c in patch.get("changes", [])
                                   if c.get("class")}),
                "validation": patch.get("validation"),
            })
    except Exception:
        # Roll back whatever was already written, using in-memory originals.
        restored = []
        for rel_path in written:
            patch = next(p for p in targets if p["path"] == rel_path)
            try:
                _atomic_write(patch["abs_path"], originals[patch["abs_path"]])
                restored.append(rel_path)
            except OSError:
                pass
        raise PatchError(
            f"apply failed mid-batch; restored {len(restored)}/{len(written)} "
            f"already-written file(s). Backups: {backup_root}")

    manifest = {
        "kind": "piquachu-rollback-manifest",
        "version": 1,
        "created_at": _dt.datetime.now(_dt.timezone.utc)
                      .replace(microsecond=0).isoformat(),
        "root": target_root,          # LOCAL artifact (needed for rollback)
        "backup_dir": backup_root,    # LOCAL artifact — do not publish
        "local_artifact": True,
        "rollback_command": "python cipher_cli.py patch --rollback <this file>",
        "files": manifest_files,
    }
    manifest_path = os.path.join(backup_root, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    for patch in targets:
        patch["rollback_manifest"] = manifest_path
    return written


def rollback(manifest_path: str) -> list[str]:
    """Restore every file recorded in a rollback manifest — refusing any file
    whose current content does not match the recorded post-apply hash (i.e.
    the developer edited it afterwards)."""
    import json
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    if manifest.get("kind") != "piquachu-rollback-manifest":
        raise PatchError(f"not a PiQuaChu rollback manifest: {manifest_path}")
    root = manifest.get("root")
    backup_dir = manifest.get("backup_dir")
    if not root or not backup_dir or not os.path.isdir(root):
        raise PatchError("manifest root/backup missing — cannot roll back")

    conflicts, restores = [], []
    for entry in manifest.get("files", []):
        path = os.path.join(root, entry["path"])
        if not os.path.isfile(path) or os.path.islink(path):
            conflicts.append(f"{entry['path']}: missing or not a regular file")
            continue
        with open(path, "rb") as fh:
            current = fh.read()
        if _sha256(current) != entry.get("new_sha256"):
            conflicts.append(
                f"{entry['path']}: modified after apply "
                f"(hash mismatch) — refusing to clobber")
            continue
        restores.append((path, os.path.join(backup_dir, entry["backup"])))
    if conflicts:
        raise PatchConflictError("rollback refused:\n  " + "\n  ".join(conflicts))
    restored = []
    for path, backup in restores:
        with open(backup, "rb") as fh:
            data = fh.read()
        _atomic_write(path, data)
        restored.append(os.path.relpath(path, root).replace(os.sep, "/"))
    return restored


# ---------------------------------------------------------------------------
# GitHub PR — opt-in, previewed, scope-checked, confirmed (never default)
# ---------------------------------------------------------------------------

_GITHUB_API = "https://api.github.com"
_PR_WRITE_SCOPES = {"repo", "public_repo", "repo:status"}


def github_pr_preview(repo: str, patches: list[dict], *,
                      branch: str | None = None, base: str | None = None,
                      title: str | None = None,
                      body: str | None = None) -> dict:
    """Compose the exact PR title/body/file list WITHOUT any network I/O, so
    the operator can review before a token is ever used."""
    branch = branch or ("piquachu-pqc-patch-" +
                        hashlib.sha256(
                            (repo + str(len(patches))).encode()).hexdigest()[:8])
    pr_title = title or "[PiQuaChu] Post-quantum remediation patches"
    summary_lines = []
    files = []
    for p in patches:
        if p.get("diff"):
            summary_lines.append(
                f"- `{p['path']}`: "
                + "; ".join(c["what"] for c in p["changes"][:6]))
            files.append({"path": p["path"],
                          "changes": len(p.get("changes", [])),
                          "classes": sorted({c.get("class")
                                             for c in p.get("changes", [])
                                             if c.get("class")}),
                          "rule_ids": p.get("rule_ids", []),
                          "old_sha256": p.get("old_sha256"),
                          "new_sha256": p.get("new_sha256")})
    pr_body = body or (
        "Automatic PQC remediation patches generated by PiQuaChu "
        "(AST-based, no source code left the host).\n\n"
        "Changes:\n" + ("\n".join(summary_lines) or "- (none)") +
        "\n\nReview classes:\n"
        "- `safe-mechanical`: semantics-preserving (CSPRNG swaps)\n"
        "- `conditional-candidate`: applied only after review — preconditions "
        "are listed in the patch manifest\n"
        "- `manual-only`: deliberately not rewritten (ECB/DES/PQC migrations)\n\n"
        "⚠ Check key rotation/interop impact before merging.")
    return {
        "repo": repo, "branch": branch, "base": base,
        "title": pr_title, "body": pr_body,
        "files": files,
        "diff_bytes": sum(len(p.get("diff") or "") for p in patches),
        "network_calls_made": False,
    }


def validate_github_token(token: str) -> dict:
    """Verify the token authenticates and carries write scopes BEFORE any
    repository mutation. Classic PATs are checked via X-OAuth-Scopes; fine-
    grained tokens expose no scope header and are reported as unverified
    (documented limitation — GitHub does not expose their permissions here)."""
    import requests
    if not token:
        raise PatchError("GITHUB_TOKEN is not set — PR creation aborted "
                         "before any network call")
    try:
        resp = requests.get(
            f"{_GITHUB_API}/user",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json"},
            timeout=30)
    except Exception as exc:
        raise PatchError(f"GitHub token validation failed before any write: {exc}") from exc
    if resp.status_code == 401:
        raise PatchError("GitHub token rejected (401) — no PR was created")
    if resp.status_code != 200:
        raise PatchError(f"GitHub token check returned HTTP {resp.status_code} "
                         f"— refusing to proceed with repository changes")
    scopes = (resp.headers.get("X-OAuth-Scopes") or "").strip()
    accepted = (resp.headers.get("X-Accepted-OAuth-Scopes") or "").strip()
    scope_set = {s.strip() for s in scopes.split(",") if s.strip()}
    if scope_set and not (scope_set & _PR_WRITE_SCOPES):
        raise PatchError(
            f"token lacks write scopes (has: {sorted(scope_set)}; needs one of "
            f"{sorted(_PR_WRITE_SCOPES)}) — no PR was created")
    return {
        "login": resp.json().get("login"),
        "scopes": sorted(scope_set),
        "accepted_scopes_header": accepted,
        "mode": "classic" if scope_set else "fine-grained-unverified",
    }


def github_pull_request(repo: str, patches: list[dict],
                         branch: str | None = None, base: str = "main",
                         title: str | None = None, body: str | None = None,
                         *, confirm: bool = False,
                         token: str | None = None) -> str:
    """Create a branch, commit the patch files and open a PR via the GitHub
    REST API. Returns the PR HTML URL.

    Refuses without explicit confirmation (confirm=True) — the default call
    performs zero network I/O. Validates the token's scopes before the first
    repository mutation; uses the configured token only after that check.
    """
    if not confirm:
        raise PatchError(
            "PR creation requires explicit confirmation: preview the PR "
            "(github_pr_preview / --pr prints it) and pass confirm=True "
            "(--yes). No network call was made.")
    import requests

    token = token or os.environ.get("GITHUB_TOKEN")
    validate_github_token(token)   # raises before any write when invalid

    if not patches or not any(p.get("diff") for p in patches):
        raise PatchError("No patches to push — no PR was created.")

    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github+json"}
    branch = branch or ("piquachu-pqc-patch-" + os.urandom(4).hex())

    repo_info = requests.get(f"{_GITHUB_API}/repos/{repo}", headers=headers,
                             timeout=30)
    repo_info.raise_for_status()
    default_branch = repo_info.json().get("default_branch", base)
    ref = requests.get(f"{_GITHUB_API}/repos/{repo}/git/ref/heads/{default_branch}",
                       headers=headers, timeout=30)
    ref.raise_for_status()
    sha = ref.json()["object"]["sha"]

    create = requests.post(f"{_GITHUB_API}/repos/{repo}/git/refs",
                           headers=headers,
                           json={"ref": f"refs/heads/{branch}", "sha": sha},
                           timeout=30)
    create.raise_for_status()

    for patch in patches:
        if not patch.get("diff"):
            continue
        content = base64.b64encode(patch["new_content"].encode("utf-8")).decode("ascii")
        upload = requests.put(f"{_GITHUB_API}/repos/{repo}/contents/{patch['path']}",
                              headers=headers,
                              json={"message": f"[PiQuaChu] PQC remediation: "
                                               f"{patch['path']}",
                                    "content": content, "branch": branch},
                              timeout=30)
        upload.raise_for_status()

    pr_title, pr_body = None, None
    if title:
        pr_title = title
    if body:
        pr_body = body
    preview = github_pr_preview(repo, patches, branch=branch, base=base,
                                title=pr_title, body=pr_body)
    pr = requests.post(f"{_GITHUB_API}/repos/{repo}/pulls", headers=headers,
                       json={"title": preview["title"], "head": branch,
                             "base": default_branch,
                             "body": preview["body"]}, timeout=30)
    pr.raise_for_status()
    return pr.json()["html_url"]
