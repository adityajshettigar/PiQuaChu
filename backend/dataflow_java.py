# backend/dataflow_java.py
"""
dataflow_java.py — bounded Java AST / constant-propagation pass
===============================================================
Uses ``javalang`` (already pinned in requirements) as an **optional** parser.
When the parser is missing or a file does not parse under its grammar, the file
is skipped and counted in diagnostics — the engine never silently drops results
nor claims Java data-flow coverage it does not have.

Documented scope
----------------
Implemented: local ``String`` constant propagation (literals, ``+`` concatenation,
same-method assignments), static-import/fully-qualified qualifier resolution,
single-return wrapper forwarding (depth 1), and value-dependent JCA sink
classification for MessageDigest / KeyPairGenerator / KeyAgreement / Signature /
Cipher / Mac / SSLContext and ``new Random(seed)``.

NOT implemented: interprocedural data-flow beyond depth-1 wrappers, field/static
state across methods, reflection/string-building beyond constant ``+``, and any
Java version-specific grammar outside javalang's supported subset.
"""

from __future__ import annotations

import os

import evidence

try:  # optional dependency — behavior is explicit when absent
    import javalang
    JAVALANG_AVAILABLE = True
    JAVALANG_VERSION = getattr(javalang, "__version__", "unknown")
except Exception:  # pragma: no cover - environment dependent
    javalang = None
    JAVALANG_AVAILABLE = False
    JAVALANG_VERSION = None

ENGINE = "dataflow-java"
LANGUAGE = "java"
_EXCLUDED_DIRS = {"venv", ".venv", "node_modules", ".git", "dist", "build",
                  "__pycache__", "target", "out",
                  ".piquachu-backups", ".piquachu-patches"}
_UNRESOLVED_RULE = "dataflow-unresolved-algorithm-java"

# qualifier -> {lowercased algorithm value: rule id}
_VALUE_RULES: dict[str, dict[str, str]] = {
    # Cipher transformations are classified by _cipher_rule, not a prefix map.
    "Cipher": {},
    "MessageDigest": {
        "md5": "weak-crypto-java-md5",
        "md2": "weak-crypto-java-md5",
        "sha-1": "weak-crypto-java-sha1",
        "sha1": "weak-crypto-java-sha1",
    },
    "KeyPairGenerator": {
        "rsa": "deprecated-rsa-java",
        "ec": "deprecated-ecdh-java",
        "ecdh": "deprecated-ecdh-java",
        "dh": "deprecated-ecdh-java",
        "diffiehellman": "deprecated-ecdh-java",
        "dsa": "deprecated-ecdsa-java",
        "kyber": "pqc-bc-kyber-java",
        "ml-kem": "pqc-bc-kyber-java",
        "dilithium": "pqc-bc-dilithium-java",
        "ml-dsa": "pqc-bc-dilithium-java",
    },
    "KeyAgreement": {
        "ecdh": "deprecated-ecdh-java",
        "dh": "deprecated-ecdh-java",
        "diffiehellman": "deprecated-ecdh-java",
        "kyber": "pqc-bc-kyber-java",
        "ml-kem": "pqc-bc-kyber-java",
    },
    "Signature": {
        "ecdsa": "deprecated-ecdsa-java",
        "ed25519": "deprecated-ecdsa-java",
        "ed448": "deprecated-ecdsa-java",
        "md5withrsa": "deprecated-ecdsa-java",
        "sha1withrsa": "deprecated-ecdsa-java",
        "dilithium": "pqc-bc-dilithium-java",
        "ml-dsa": "pqc-bc-dilithium-java",
        "sphincsplus": "pqc-bc-sphincs-java",
        "sphincs+": "pqc-bc-sphincs-java",
        "slh-dsa": "pqc-bc-sphincs-java",
    },
    "Mac": {
        "hmacmd5": "weak-crypto-java-md5",
        "hmacsha1": "weak-crypto-java-sha1",
    },
    "SSLContext": {
        "tlsv1": "deprecated-tlsv1-java",
        "tlsv1.1": "deprecated-tlsv1-java",
        "sslv3": "deprecated-tlsv1-java",
    },
}

_MD5_ONLY = {"md5", "md2"}


def _strip_literal(value: str) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _cipher_rule(value: str) -> str | None:
    low = value.strip().lower()
    if "/ecb/" in low:
        return "deprecated-ecb-java"
    if "rsa" in low and "nopadding" in low:
        return "deprecated-rsa-nopadding-java"
    if any(token in low for token in ("des", "3des", "desede", "rc4")):
        return "deprecated-des-java"
    if "/" not in low and low in ("aes", "des", "desede", "blowfish"):
        return "deprecated-cipher-default-mode-java"
    return None


class _JavaFlow:
    def __init__(self, path: str, metadata: dict, root: str | None = None):
        self.path = path
        self.root = root
        self.metadata = metadata
        self.findings: list[dict] = []
        self.unresolved = 0
        self.wrappers: dict[str, dict] = {}

    # -- value resolution -------------------------------------------------
    def eval(self, node, env: dict) -> tuple:
        """(KNOWN, value, None) | (UNRESOLVED, None, source) | (UNKNOWN, None, None)"""
        if javalang is not None and isinstance(node, javalang.tree.Literal):
            return ("known", _strip_literal(node.value), None)
        if javalang is not None and isinstance(node, javalang.tree.BinaryOperation):
            if node.operator == "+":
                left = self.eval(node.operandl, env)
                right = self.eval(node.operandr, env)
                if left[0] == "known" and right[0] == "known":
                    return ("known", str(left[1]) + str(right[1]), None)
            return ("unknown", None, None)
        if javalang is not None and isinstance(node, javalang.tree.MemberReference):
            name = node.member
            if name in env:
                return env[name]
            return ("unknown", None, None)
        if javalang is not None and isinstance(node, (javalang.tree.MethodInvocation,
                                                      javalang.tree.ClassCreator)):
            return ("unresolved", None, "method-call")
        return ("unknown", None, None)

    def _emit(self, rule_id: str, node, *, observed, source_desc, sink_desc,
              evidence_type: str, confidence: str, signature: str,
              rationale: str, inconclusive: bool = False) -> None:
        meta = self.metadata.get(rule_id, {}) if self.metadata else {}
        position = getattr(node, "position", None)
        line = position.line if position is not None else self._line_hint
        finding = {
            "file": self.path,
            "line": line or 0,
            "vulnerability": rule_id,
            "recommendation": "",
            "severity": "INFO" if inconclusive else meta.get("severity", "WARNING"),
        }
        self.findings.append(evidence.annotate(
            finding, engine=ENGINE, evidence_type=evidence_type,
            confidence=confidence, language=LANGUAGE,
            evidence_signature=signature, source_description=source_desc,
            sink_description=sink_desc,
            observed_value=evidence.safe_observed_value(observed),
            scope=self._scope, rationale=rationale,
            limitations=("Bounded intraprocedural Java propagation; parser support "
                         "is javalang's grammar subset and does not prove runtime "
                         "behaviour."),
            inconclusive=inconclusive, informational=inconclusive,
            metadata=self.metadata, root=self.root,
        ))

    _scope = ""
    _line_hint = 0

    # -- walking ----------------------------------------------------------
    @staticmethod
    def _statements_of(body):
        """javalang exposes method bodies as a list of statements (0.13); some
        helpers wrap them in a BlockStatement."""
        if body is None:
            return []
        if isinstance(body, list):
            return body
        statements = getattr(body, "statements", None)
        return statements if isinstance(statements, list) else []

    def _walk_block(self, statements, env) -> None:
        for stmt in statements or []:
            self._walk_statement(stmt, env)

    def _walk_statement(self, stmt, env) -> None:
        if javalang is None:
            return
        position = getattr(stmt, "position", None)
        if position is not None:
            self._line_hint = position.line
        if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
            for declarator in stmt.declarators:
                if declarator.initializer is not None:
                    env[declarator.name] = self.eval(declarator.initializer, env)
                self._visit_expr(declarator.initializer, env)
        elif isinstance(stmt, javalang.tree.FieldDeclaration):
            for declarator in stmt.declarators:
                if declarator.initializer is not None:
                    env[declarator.name] = self.eval(declarator.initializer, env)
        elif isinstance(stmt, javalang.tree.StatementExpression):
            self._visit_expr(stmt.expression, env)
        elif isinstance(stmt, (javalang.tree.IfStatement,)):
            self._walk_statement(stmt.then_statement, dict(env))
            if stmt.else_statement is not None:
                self._walk_statement(stmt.else_statement, dict(env))
        elif isinstance(stmt, javalang.tree.BlockStatement):
            self._walk_block(stmt.statements, env)
        elif isinstance(stmt, list):
            self._walk_block(stmt, env)
        elif isinstance(stmt, javalang.tree.ReturnStatement):
            self._visit_expr(stmt.expression, env)
        elif isinstance(stmt, javalang.tree.ForStatement):
            self._walk_block(stmt.body, env)
            control = getattr(stmt, "control", None)
            for init in (getattr(control, "init", None) or []) if control else []:
                self._walk_statement(init, env)
        elif isinstance(stmt, javalang.tree.TryStatement):
            for resource in stmt.resources or []:
                self._walk_statement(resource, env)
            self._walk_block(stmt.block, env)
        elif isinstance(stmt, javalang.tree.VariableDeclaration):
            for declarator in stmt.declarators:
                if declarator.initializer is not None:
                    env[declarator.name] = self.eval(declarator.initializer, env)

    def _visit_expr(self, node, env) -> None:
        if node is None or javalang is None:
            return
        if isinstance(node, javalang.tree.Assignment):
            value = self.eval(node.value, env)
            target = node.expressionl
            if isinstance(target, javalang.tree.MemberReference):
                env[target.member] = value
            self._visit_expr(node.value, env)
            return
        if isinstance(node, javalang.tree.MethodInvocation):
            self._handle_invocation(node, env)
            for arg in node.arguments or []:
                self._visit_expr(arg, env)
            return
        if isinstance(node, javalang.tree.ClassCreator):
            self._handle_creator(node, env)
            for arg in node.arguments or []:
                self._visit_expr(arg, env)
            return
        # javalang does not expose a generic children API; nested expressions are
        # visited through their owning declaration/assignment/invocation.

    def _handle_creator(self, node, env) -> None:
        type_name = getattr(node, "type", None)
        name = getattr(type_name, "name", "") if type_name is not None else ""
        if name == "Random" and node.arguments:
            got = self.eval(node.arguments[0], env)
            if got[0] == "known" and str(got[1]).isdigit():
                self._emit("weak-randomness-java", node, observed=got[1],
                           source_desc="constant seed", sink_desc="new Random(seed)",
                           evidence_type="constant_propagated", confidence="high",
                           signature="call:new Random|seed",
                           rationale="java.util.Random seeded with a constant.")

    def _handle_invocation(self, node, env) -> None:
        member = node.member
        qualifier = node.qualifier or ""
        short = qualifier.split(".")[-1] if qualifier else ""

        # Wrapper forwarding (depth 1): helper(args) -> getInstance(arg)
        wrapper = self.wrappers.get(member) if not qualifier else None
        if wrapper and node.arguments:
            idx = wrapper["arg_index"]
            if idx < len(node.arguments):
                got = self.eval(node.arguments[idx], env)
                rule = self._classify(wrapper["qualifier"], got)
                if rule:
                    self._emit(rule, node, observed=got[1],
                               source_desc="wrapper argument",
                               sink_desc=f"wrapper:{member}->"
                                         f"{wrapper['qualifier']}.getInstance",
                               evidence_type="data_flow", confidence="medium",
                               signature=f"wrapper:{member}|algo",
                               rationale="Value forwarded through a local wrapper "
                                         "method into a JCA getInstance call.")
            return

        if member != "getInstance":
            return
        if short not in _VALUE_RULES:
            return
        if not node.arguments:
            return
        got = self.eval(node.arguments[0], env)
        if short == "Cipher":
            if got[0] == "known":
                rule = _cipher_rule(str(got[1]))
                if rule:
                    self._emit(rule, node, observed=got[1],
                               source_desc="local constant propagation",
                               sink_desc="Cipher.getInstance(transformation)",
                               evidence_type="constant_propagated",
                               confidence="high",
                               signature="call:Cipher.getInstance|transform",
                               rationale="Resolved cipher transformation through "
                                         "local assignments.")
            elif got[0] == "unresolved":
                self._unresolved(node, "Cipher.getInstance", got[2])
            return
        rule = self._classify(short, got)
        if rule:
            self._emit(rule, node, observed=got[1],
                       source_desc="local constant propagation",
                       sink_desc=f"{short}.getInstance(algorithm)",
                       evidence_type="constant_propagated", confidence="high",
                       signature=f"call:{short}.getInstance|algo",
                       rationale="Resolved JCA algorithm through local assignments.")
        elif got[0] == "unresolved":
            self._unresolved(node, f"{short}.getInstance", got[2])

    def _unresolved(self, node, sink, source) -> None:
        self.unresolved += 1
        self._emit(_UNRESOLVED_RULE, node, observed=None,
                   source_desc=source or "dynamic", sink_desc=sink,
                   evidence_type="inconclusive", confidence="inconclusive",
                   signature=f"call:{sink}|algo",
                   rationale=("JCA algorithm could not be resolved statically; "
                              "reported as inconclusive, not as a pass."),
                   inconclusive=True)

    def _classify(self, qualifier: str, got: tuple) -> str | None:
        if got[0] != "known":
            return None
        value = str(got[1]).strip().lower()
        mapping = _VALUE_RULES.get(qualifier, {})
        if value in mapping:
            return mapping[value]
        # RSA-family signature strings ("SHA256withRSA" etc.) are classical signatures.
        if qualifier == "Signature" and "withrsa" in value:
            return "deprecated-ecdsa-java"
        return None

    # -- wrapper discovery -------------------------------------------------
    def _register_wrappers(self, tree) -> None:
        if javalang is None:
            return
        for _path, declaration in tree.filter(javalang.tree.MethodDeclaration):
            stmts = [s for s in self._statements_of(declaration.body)
                     if isinstance(s, javalang.tree.ReturnStatement)]
            if len(stmts) != 1:
                continue
            call = stmts[0].expression
            if not isinstance(call, javalang.tree.MethodInvocation) or \
                    call.member != "getInstance":
                continue
            qualifier = (call.qualifier or "").split(".")[-1]
            if qualifier not in _VALUE_RULES or not call.arguments:
                continue
            arg = call.arguments[0]
            if not isinstance(arg, javalang.tree.MemberReference):
                continue
            params = [p.name for p in declaration.parameters]
            if arg.member not in params:
                continue
            self.wrappers[declaration.name] = {
                "qualifier": qualifier,
                "arg_index": params.index(arg.member),
            }

    def analyze_tree(self, tree) -> None:
        if javalang is None:
            return
        for type_decl in getattr(tree, "types", []) or []:
            members = getattr(type_decl, "body", None) or []
            class_env: dict = {}
            self._scope = getattr(type_decl, "name", "")
            # Static/instance field initializers (e.g. `static final String T =
            # "AES/ECB/...";`) are visible to every method in the class.
            for member in members:
                if isinstance(member, javalang.tree.FieldDeclaration):
                    for declarator in member.declarators:
                        if declarator.initializer is not None:
                            class_env[declarator.name] = self.eval(
                                declarator.initializer, class_env)
            for member in members:
                if isinstance(member, (javalang.tree.MethodDeclaration,
                                       javalang.tree.ConstructorDeclaration)):
                    env = dict(class_env)
                    self._scope = f"{getattr(type_decl, 'name', '')}." \
                                  f"{getattr(member, 'name', '<init>')}"
                    # Method parameters are dynamic by definition: record them as
                    # unresolved (not as a pass) so a config-driven getInstance
                    # argument is reported with reduced confidence.
                    for param in (member.parameters or []):
                        env[param.name] = ("unresolved", None,
                                           f"parameter:{param.name}")
                    self._walk_block(self._statements_of(member.body), env)
        self._scope = ""


def _analyze_file(path: str, metadata: dict, diagnostics: dict,
                  root: str | None = None) -> list[dict]:
    if not JAVALANG_AVAILABLE:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        tree = javalang.parse.parse(source)
    except Exception as exc:  # parser/lexer/token errors — recorded, never fatal
        diagnostics["parser_failures"]["java"] = \
            diagnostics["parser_failures"].get("java", 0) + 1
        diagnostics.setdefault("parser_failure_files", []).append(
            evidence.relativize(path, root))
        diagnostics.setdefault("parser_failure_errors", []).append(
            f"{evidence.relativize(path, root)}: {type(exc).__name__}")
        return []
    diagnostics["files_analyzed"]["java"] = \
        diagnostics["files_analyzed"].get("java", 0) + 1
    flow = _JavaFlow(path, metadata, root=root)
    flow._register_wrappers(tree)
    flow.analyze_tree(tree)
    diagnostics["unresolved_values"]["java"] = \
        diagnostics["unresolved_values"].get("java", 0) + flow.unresolved
    return flow.findings


def analyze_directory(target_directory: str, metadata: dict | None = None) -> dict:
    from compliance import load_rule_metadata
    metadata = metadata if metadata is not None else load_rule_metadata()
    diagnostics: dict = {"parser_failures": {}, "files_analyzed": {},
                         "unresolved_values": {}, "parser_failure_files": [],
                         "engines": {}, "javalang_available": JAVALANG_AVAILABLE,
                         "javalang_version": JAVALANG_VERSION}
    findings: list[dict] = []
    if not JAVALANG_AVAILABLE:
        diagnostics["engines"][ENGINE] = {
            "engine": ENGINE, "engine_version": evidence.ENGINE_VERSION,
            "language": LANGUAGE, "status": "unavailable",
            "note": "javalang not installed — Java data-flow engine skipped",
        }
        return {"findings": [], "diagnostics": diagnostics}
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for name in files:
            if not name.endswith(".java"):
                continue
            findings.extend(_analyze_file(os.path.join(root, name), metadata,
                                          diagnostics, root=target_directory))
    diagnostics["engines"][ENGINE] = {
        "engine": ENGINE, "engine_version": evidence.ENGINE_VERSION,
        "language": LANGUAGE, "findings": len(findings),
        "parser": f"javalang {JAVALANG_VERSION}",
    }
    return {"findings": findings, "diagnostics": diagnostics}
