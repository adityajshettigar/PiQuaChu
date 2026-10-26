# backend/dataflow_python.py
"""
dataflow_python.py — bounded Python data-flow / constant propagation
====================================================================
Supplementary engine. It does **not** replace the semgrep or native AST engine;
it tracks statically-resolvable values through common local constructs and
follows them into value-dependent cryptographic sinks that literal matching
misses (for example ``algo = "md5"; hashlib.new(algo)`` or a mode passed by
variable).

Documented scope
----------------
Implemented: intraprocedural constant propagation over literal/constant
assignments, alias imports, assignment chains, statically-resolvable string
concatenation/formatting, simple ``if/else`` joins where both branches agree,
single-return wrapper forwarding within a module, and unresolved tracking for
``os.environ``/``os.getenv``/config objects.

NOT implemented (do not claim otherwise): interprocedural taint analysis,
attribute/field tracking, class-method flows, callback/closure flows,
``eval``/``exec`` of scanned code, or execution of the scanned project.

Bounds: per-file only, single-return wrapper depth 1, no path explosion. A file
that fails to parse is skipped and counted; it never discards other files.
Secrets: environment/config values are never rendered — only the source name is
recorded.
"""

from __future__ import annotations

import ast
import os

import evidence

ENGINE = "dataflow-py"
LANGUAGE = "python"
_PYTHON_EXTS = {".py", ".pyx", ".pxd", ".pyi"}
_EXCLUDED_DIRS = {"venv", ".venv", "node_modules", ".git", "dist", "build",
                  "__pycache__", "site-packages", "target",
                  ".piquachu-backups", ".piquachu-patches"}

# Value states
KNOWN = "known"
UNRESOLVED = "unresolved"
UNKNOWN = "unknown"

_UNRESOLVED_SOURCES = {"config", "settings", "cfg", "conf"}

# Algorithm-value -> rule id maps. Values are case-folded before lookup.
_HASH_ALGO_RULES = {
    "md5": "weak-crypto-python-md5",
    "sha1": "weak-crypto-python-sha1",
    "sha-1": "weak-crypto-python-sha1",
}
_KEM_ALGO_RULES = {
    "ml-kem-512": "pqc-mlkem-python",
    "ml-kem-768": "pqc-mlkem-python",
    "ml-kem-1024": "pqc-mlkem-python",
    "kyber512": "pqc-mlkem-python",
    "kyber768": "pqc-mlkem-python",
    "kyber1024": "pqc-mlkem-python",
}
_SIG_ALGO_RULES = {
    "ml-dsa-44": "pqc-mldsa-python",
    "ml-dsa-65": "pqc-mldsa-python",
    "ml-dsa-87": "pqc-mldsa-python",
    "dilithium2": "pqc-mldsa-python",
    "dilithium3": "pqc-mldsa-python",
    "dilithium5": "pqc-mldsa-python",
    "slh-dsa-sha2-128s": "pqc-slhdsa-python",
    "sphincs": "pqc-slhdsa-python",
    "falcon-512": "pqc-fndsa-python",
    "falcon-1024": "pqc-fndsa-python",
}
_MODE_RULES = {"ecb": "deprecated-ecb-python"}
_UNRESOLVED_RULE = "dataflow-unresolved-algorithm-python"

# Value-independent crypto API patterns the data-flow pass adds beyond literal
# rules: mode objects and classical block ciphers selected by API name.
_MODE_OBJECT_RULES = {
    "ECB": "deprecated-ecb-python",
}
_CLASSICAL_CIPHER_RULES = {
    "TripleDES": "deprecated-des-python",
    "ARC4": "deprecated-rc4-python",
    "Blowfish": "deprecated-blowfish-python",
}

_UNRESOLVED_LIMITATION = (
    "Value originates from an environment/config/dynamic source and was not "
    "statically resolved; the algorithm/parameter could not be proven."
)


def _literal(value) -> tuple:
    return (KNOWN, value, None)


def _unresolved(source: str) -> tuple:
    return (UNRESOLVED, None, source)


def _unknown() -> tuple:
    return (UNKNOWN, None, None)


def _collect_aliases(tree: ast.AST) -> dict:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                canonical = f"{mod}.{alias.name}" if mod else alias.name
                aliases[alias.asname or alias.name] = canonical
    return aliases


def _dotted(node, aliases: dict) -> str:
    """Resolve an Attribute/Name chain into a dotted path through aliases."""
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func, aliases)
    return ""


def _module_func(func_node, aliases: dict) -> tuple[str, str]:
    """Return (module, function) for a call target, resolving alias imports."""
    if isinstance(func_node, ast.Name):
        resolved = aliases.get(func_node.id, func_node.id)
        if "." in resolved:
            mod, _, fn = resolved.rpartition(".")
            return mod, fn
        return "", resolved
    if isinstance(func_node, ast.Attribute):
        mod = _dotted(func_node.value, aliases)
        return mod, func_node.attr
    return "", ""


class _Scope:
    __slots__ = ("env",)

    def __init__(self, env: dict):
        self.env = dict(env)


class _Flow:
    """Single-file bounded flow analysis."""

    def __init__(self, path: str, metadata: dict, root: str | None = None):
        self.path = path
        self.root = root
        self.metadata = metadata
        self.aliases: dict[str, str] = {}
        self.wrappers: dict[str, dict] = {}
        self.findings: list[dict] = []
        self.unresolved = 0
        self._visited_calls: set[int] = set()

    # -- value evaluation -------------------------------------------------
    def eval(self, node, env: dict) -> tuple:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, bytes)):
                return _literal(node.value)
            return _unknown()
        if isinstance(node, ast.Name):
            return env.get(node.id, _unknown())
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.eval(node.left, env)
            right = self.eval(node.right, env)
            if left[0] == KNOWN and right[0] == KNOWN and \
                    isinstance(left[1], type(right[1])):
                return _literal(left[1] + right[1])
            return _unknown()
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return self._eval_format(node, env)
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(value.value)
                elif isinstance(value, ast.FormattedValue):
                    got = self.eval(value.value, env)
                    if got[0] != KNOWN:
                        return _unknown()
                    parts.append(got[1])
                else:
                    return _unknown()
            return _literal("".join(str(p) for p in parts))
        if isinstance(node, ast.Call):
            return self._eval_call(node, env)
        if isinstance(node, ast.Subscript):
            return self._eval_subscript(node, env)
        if isinstance(node, ast.Attribute):
            if _dotted(node.value, self.aliases).split(".")[0] in _UNRESOLVED_SOURCES:
                return _unresolved(f"config:{node.attr}")
            return _unknown()
        if isinstance(node, ast.IfExp):
            left = self.eval(node.body, env)
            right = self.eval(node.orelse, env)
            if left[0] == KNOWN and right[0] == KNOWN and left[1] == right[1]:
                return left
            return _unknown()
        return _unknown()

    def _eval_format(self, node, env) -> tuple:
        """`"%s" % x` where every operand is statically known."""
        fmt = self.eval(node.left, env)
        if fmt[0] != KNOWN or not isinstance(fmt[1], (str, bytes)):
            return _unknown()
        right = node.right
        values = right.elts if isinstance(right, (ast.Tuple, ast.List)) else [right]
        resolved = []
        for item in values:
            got = self.eval(item, env)
            if got[0] != KNOWN:
                return _unknown()
            resolved.append(got[1])
        try:
            if isinstance(fmt[1], bytes):
                return _literal(fmt[1] % tuple(resolved))
            return _literal(fmt[1] % tuple(resolved))
        except (TypeError, ValueError):
            return _unknown()

    def _eval_subscript(self, node, env) -> tuple:
        base = _dotted(node.value, self.aliases)
        if base == "os.environ":
            key = self.eval(node.slice, env)
            return _unresolved(f"env:{key[1] if key[0] == KNOWN else '?'}")
        if base.split(".")[0] in _UNRESOLVED_SOURCES:
            return _unresolved("config:subscript")
        # `constants["MODE"]` style dict lookups are not tracked (bounded scope).
        return _unknown()

    def _eval_call(self, node, env) -> tuple:
        mod, fn = _module_func(node.func, self.aliases)
        if fn in ("getenv",) and mod == "os":
            return _unresolved("env")
        if mod == "os" and fn == "environ":
            return _unresolved("env")
        if fn == "get" and _dotted(node.func.value, self.aliases) in (
                "os.environ",):
            key = self.eval(node.args[0], env) if node.args else _unknown()
            return _unresolved(f"env:{key[1] if key[0] == KNOWN else '?'}")
        if fn == "get" and _dotted(node.func.value, self.aliases).split(".")[0] \
                in _UNRESOLVED_SOURCES:
            return _unresolved("config:get")
        if fn in ("str", "bytes") and node.args:
            got = self.eval(node.args[0], env)
            if got[0] == KNOWN:
                try:
                    return _literal(str(got[1])
                                    if fn == "str" else bytes(got[1]))
                except (TypeError, ValueError):
                    return _unknown()
            return _unknown()
        if fn == "format" and isinstance(node.func, ast.Attribute):
            base = self.eval(node.func.value, env)
            if base[0] != KNOWN or not isinstance(base[1], str):
                return _unknown()
            parts = []
            for arg in node.args:
                got = self.eval(arg, env)
                if got[0] != KNOWN:
                    return _unknown()
                parts.append(got[1])
            kwargs = {}
            for kw in node.keywords or []:
                got = self.eval(kw.value, env)
                if got[0] != KNOWN:
                    return _unknown()
                kwargs[kw.arg] = got[1]
            try:
                return _literal(base[1].format(*parts, **kwargs))
            except (IndexError, KeyError, ValueError):
                return _unknown()
        return _unknown()

    # -- sinks ------------------------------------------------------------
    def _emit(self, rule_id, node, *, observed, source_desc, sink_desc,
              evidence_type, confidence, signature, rationale,
              inconclusive=False, informational=False):
        meta = self.metadata.get(rule_id, {}) if self.metadata else {}
        if inconclusive:
            severity = "INFO"
        else:
            severity = meta.get("severity", "WARNING")
        finding = {
            "file": self.path,
            "line": getattr(node, "lineno", 0) or 0,
            "column": getattr(node, "col_offset", None),
            "vulnerability": rule_id,
            "recommendation": "",
            "severity": severity,
        }
        annotated = evidence.annotate(
            finding, engine=ENGINE, evidence_type=evidence_type,
            confidence=confidence, language=LANGUAGE,
            evidence_signature=signature,
            source_description=source_desc, sink_description=sink_desc,
            observed_value=evidence.safe_observed_value(observed),
            scope=self._scope_name, rationale=rationale,
            limitations=("Bounded intraprocedural propagation; cannot prove "
                         "runtime configuration, protocol negotiation or "
                         "implementation correctness.")
            if not inconclusive else _UNRESOLVED_LIMITATION,
            inconclusive=inconclusive, informational=informational,
            metadata=self.metadata, root=self.root,
        )
        self.findings.append(annotated)

    _scope_name = ""

    def _classify(self, value: str, mapping: dict) -> str | None:
        return mapping.get(str(value).strip().lower())

    def _check_value_sink(self, node, env, mod, fn) -> bool:
        """Value-dependent sinks: (module, function) -> algorithm/mode arg."""
        key = (mod, fn)
        if key == ("hmac", "new"):
            # hmac.new(key, msg, digestmod) — algorithm is digestmod, not arg 0.
            digest = None
            if len(node.args) > 2:
                digest = self.eval(node.args[2], env)
            for kw in node.keywords or []:
                if kw.arg == "digestmod":
                    digest = self.eval(kw.value, env)
            if digest and digest[0] == KNOWN:
                rule = self._classify(digest[1], _HASH_ALGO_RULES)
                if rule:
                    self._emit(rule, node, observed=digest[1],
                               source_desc="local constant propagation",
                               sink_desc="hmac.new(digestmod=…)",
                               evidence_type="constant_propagated",
                               confidence="high",
                               signature="call:hmac.new|digestmod",
                               rationale="Resolved hmac digest algorithm "
                                         "through local assignments.")
            return True

        algo_map = None
        if key == ("hashlib", "new"):
            algo_map = _HASH_ALGO_RULES
        elif key == ("oqs", "KeyEncapsulation"):
            algo_map = _KEM_ALGO_RULES
        elif key == ("oqs", "Signature"):
            algo_map = _SIG_ALGO_RULES
        if algo_map is not None:
            args = list(node.args)
            if not args and node.keywords:
                return False
            if not args:
                return False
            got = self.eval(args[0], env)
            if got[0] == KNOWN:
                rule = self._classify(got[1], algo_map)
                if rule:
                    self._emit(rule, node, observed=got[1],
                               source_desc="local constant propagation",
                               sink_desc=f"{mod}.{fn}(algorithm=…)",
                               evidence_type="constant_propagated",
                               confidence="high",
                               signature=f"call:{mod}.{fn}|algo",
                               rationale=("Resolved algorithm value "
                                          f"'{evidence.safe_observed_value(got[1])}' "
                                          "through local assignments."))
                return True
            if got[0] == UNRESOLVED:
                self.unresolved += 1
                self._emit(_UNRESOLVED_RULE, node, observed=None,
                           source_desc=got[2] or "dynamic",
                           sink_desc=f"{mod}.{fn}(algorithm=…)",
                           evidence_type="inconclusive",
                           confidence="inconclusive",
                           signature=f"call:{mod}.{fn}|algo",
                           rationale=("Algorithm argument to "
                                      f"{mod}.{fn} could not be resolved; "
                                      "reported as inconclusive, not as a pass."),
                           inconclusive=True, informational=True)
                return True
            return False

        # Symmetric cipher mode passed by variable.
        if fn == "new" and mod in ("Crypto.Cipher.AES", "AES"):
            mode = self._resolve_mode(node, env)
            if mode is not None:
                status, value, source = mode
                if status == KNOWN:
                    rule = self._classify(value, _MODE_RULES)
                    if rule:
                        self._emit(rule, node, observed=value,
                                   source_desc="local constant propagation",
                                   sink_desc=f"{mod}.new(mode=…)",
                                   evidence_type="constant_propagated",
                                   confidence="high",
                                   signature=f"call:{mod}.new|mode",
                                   rationale=("Resolved cipher mode '%s' "
                                              "through local assignments."
                                              % evidence.safe_observed_value(value)))
                elif status == UNRESOLVED:
                    self.unresolved += 1
                    self._emit("dataflow-unresolved-mode-python", node,
                               observed=None, source_desc=source or "dynamic",
                               sink_desc=f"{mod}.new(mode=…)",
                               evidence_type="inconclusive",
                               confidence="inconclusive",
                               signature=f"call:{mod}.new|mode",
                               rationale=("Cipher mode could not be resolved; "
                                          "reported as inconclusive, not as a pass."),
                               inconclusive=True, informational=True)
            return True

        # KDF salt passed by variable: propagate to static-salt detection.
        if key == ("hashlib", "pbkdf2_hmac"):
            salt = None
            if len(node.args) > 2:
                salt = self.eval(node.args[2], env)
            for kw in node.keywords or []:
                if kw.arg == "salt":
                    salt = self.eval(kw.value, env)
            if salt and salt[0] == KNOWN and isinstance(salt[1], (str, bytes)):
                self._emit("deprecated-static-salt-python", node,
                           observed=None, source_desc="local constant",
                           sink_desc="hashlib.pbkdf2_hmac(salt=…)",
                           evidence_type="constant_propagated",
                           confidence="high",
                           signature="call:hashlib.pbkdf2_hmac|salt",
                           rationale="Salt resolves to a local constant.")
            return True
        return False

    def _resolve_mode(self, node, env):
        """Return (status, value, source) for a cipher mode argument."""
        candidates = []
        if len(node.args) > 1:
            candidates.append(node.args[1])
        for kw in node.keywords or []:
            if kw.arg in ("mode", "operation"):
                candidates.append(kw.value)
        for cand in candidates:
            if isinstance(cand, ast.Attribute) and cand.attr.startswith("MODE_"):
                return _literal(cand.attr[5:])
            got = self.eval(cand, env)
            if got[0] in (KNOWN, UNRESOLVED):
                return got
        return None

    # -- wrappers ---------------------------------------------------------
    def _register_wrappers(self, tree) -> None:
        """Single-return wrappers around a value-dependent sink, depth 1."""
        for node in tree.body if isinstance(tree, ast.Module) else []:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if len(node.body) != 1 or not isinstance(node.body[0], ast.Return):
                continue
            call = node.body[0].value
            if not isinstance(call, ast.Call):
                continue
            mod, fn = _module_func(call.func, self.aliases)
            params = [a.arg for a in node.args.args]
            if not params:
                continue
            arg_index = None
            if (mod, fn) in {("hashlib", "new"), ("hmac", "new"),
                             ("oqs", "KeyEncapsulation"), ("oqs", "Signature")} \
                    and call.args and isinstance(call.args[0], ast.Name) \
                    and call.args[0].id in params:
                arg_index = params.index(call.args[0].id)
            if arg_index is None:
                continue
            defaults: dict[int, tuple] = {}
            defaults_list = [None] * (len(params) - len(node.args.defaults)) \
                + list(node.args.defaults)
            for idx, default in enumerate(defaults_list):
                if default is not None and isinstance(default, ast.Constant) \
                        and isinstance(default.value, str):
                    defaults[idx] = _literal(default.value)
            self.wrappers[node.name] = {"params": params, "module": mod,
                                        "func": fn, "arg_index": arg_index,
                                        "defaults": defaults}

    # -- statement handling ----------------------------------------------
    def _assign_targets(self, node, env) -> None:
        value = self.eval(node.value, env)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if value[0] in (KNOWN, UNRESOLVED):
                    env[target.id] = value
                else:
                    env.pop(target.id, None)

    def _visit_block(self, stmts, env) -> None:
        for stmt in stmts:
            self._visit_stmt(stmt, env)

    def _visit_expr_calls(self, node, env) -> None:
        """Visit every Call inside an expression exactly once (innermost too)."""
        if node is None:
            return
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and id(sub) not in self._visited_calls:
                self._visited_calls.add(id(sub))
                self._visit_call(sub, env)

    def _visit_stmt(self, stmt, env) -> None:
        if isinstance(stmt, ast.Assign):
            self._assign_targets(stmt, env)
            self._visit_expr_calls(stmt.value, env)
        elif isinstance(stmt, ast.Return):
            self._visit_expr_calls(stmt.value, env)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.value is not None:
                value = self.eval(stmt.value, env)
                if value[0] in (KNOWN, UNRESOLVED):
                    env[stmt.target.id] = value
                else:
                    env.pop(stmt.target.id, None)
                self._visit_expr_calls(stmt.value, env)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            current = env.get(stmt.target.id, _unknown())
            if current[0] == KNOWN and isinstance(stmt.value, ast.Constant):
                op = stmt.op
                try:
                    if isinstance(op, ast.Add):
                        env[stmt.target.id] = _literal(current[1] + stmt.value.value)
                except TypeError:
                    env.pop(stmt.target.id, None)
        elif isinstance(stmt, ast.If):
            left = dict(env)
            self._visit_block(stmt.body, left)
            right = dict(env)
            self._visit_block(stmt.orelse, right)
            self._join(env, left, right)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            for target in ast.walk(stmt.target):
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
            self._visit_block(stmt.body, env)
        elif isinstance(stmt, (ast.While,)):
            self._visit_block(stmt.body, env)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            self._visit_block(stmt.body, env)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            outer = dict(env)
            inner = dict(env)
            for arg in stmt.args.posonlyargs + stmt.args.args + stmt.args.kwonlyargs:
                inner.pop(arg.arg, None)
            saved_scope = self._scope_name
            self._scope_name = stmt.name
            self._visit_block(stmt.body, inner)
            self._scope_name = saved_scope
            env.clear()
            env.update(outer)
        elif isinstance(stmt, ast.ClassDef):
            self._visit_block(stmt.body, dict(env))
        elif isinstance(stmt, ast.Try):
            self._visit_block(stmt.body, env)
            for handler in stmt.handlers:
                self._visit_block(handler.body, env)
            self._visit_block(stmt.orelse, env)
            self._visit_block(stmt.finalbody, env)
        elif isinstance(stmt, ast.Expr):
            self._visit_expr_calls(stmt.value, env)
        else:
            # Generic statement: still capture calls in its expressions.
            for field, value in ast.iter_fields(stmt):
                if isinstance(value, ast.AST) and not isinstance(
                        value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    self._visit_expr_calls(value, env)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, ast.AST) and not isinstance(
                                item, (ast.FunctionDef, ast.AsyncFunctionDef,
                                       ast.ClassDef)):
                            self._visit_expr_calls(item, env)

    def _join(self, env: dict, left: dict, right: dict) -> None:
        for name in set(left) | set(right):
            lv, rv = left.get(name), right.get(name)
            if lv and rv and lv[0] == KNOWN and rv[0] == KNOWN and lv[1] == rv[1]:
                env[name] = lv
            elif lv and rv and lv[0] == UNRESOLVED and rv[0] == UNRESOLVED \
                    and lv[2] == rv[2]:
                env[name] = lv
            elif lv and rv and lv[0] == KNOWN and rv[0] == KNOWN:
                # Divergent constants: the value is genuinely ambiguous, so it
                # is recorded as unresolved evidence rather than silently
                # dropping one of the branches.
                env[name] = _unresolved("join:divergent")
            else:
                env.pop(name, None)

    # -- calls ------------------------------------------------------------
    def _visit_call(self, node, env) -> None:
        mod, fn = _module_func(node.func, self.aliases)

        # Wrapper forwarding (depth 1).
        wrapper = self.wrappers.get(fn) if not mod else None
        if wrapper:
            params = wrapper["params"]
            args = list(node.args)
            idx = wrapper["arg_index"]
            got = None
            if idx < len(args):
                got = self.eval(args[idx], env)
            elif idx in wrapper.get("defaults", {}):
                got = wrapper["defaults"][idx]
            if got is not None and got[0] == KNOWN:
                mapping = _HASH_ALGO_RULES
                if wrapper["module"] == "oqs" and wrapper["func"] == "KeyEncapsulation":
                    mapping = _KEM_ALGO_RULES
                elif wrapper["module"] == "oqs" and wrapper["func"] == "Signature":
                    mapping = _SIG_ALGO_RULES
                rule = self._classify(got[1], mapping)
                if rule:
                    self._emit(rule, node, observed=got[1],
                               source_desc="wrapper argument",
                               sink_desc=f"wrapper:{fn}->"
                                         f"{wrapper['module']}.{wrapper['func']}",
                               evidence_type="data_flow", confidence="medium",
                               signature=f"wrapper:{fn}|algo",
                               rationale=("Value forwarded through local "
                                          "wrapper %s into %s.%s."
                                          % (fn, wrapper["module"],
                                             wrapper["func"])))
            if got is not None and got[0] == UNRESOLVED:
                self.unresolved += 1
                self._emit(_UNRESOLVED_RULE, node, observed=None,
                           source_desc=got[2] or "dynamic",
                           sink_desc=f"wrapper:{fn}->"
                                     f"{wrapper['module']}.{wrapper['func']}",
                           evidence_type="inconclusive",
                           confidence="inconclusive",
                           signature=f"wrapper:{fn}|algo",
                           rationale="Wrapper argument could not be resolved.",
                           inconclusive=True, informational=True)
            return

        if self._check_value_sink(node, env, mod, fn):
            return
        self._check_api_sink(node, mod, fn)

    def _check_api_sink(self, node, mod, fn) -> None:
        """Value-independent crypto API patterns (mode objects, block ciphers)."""
        if fn in _MODE_OBJECT_RULES and mod.split(".")[-1:] == ["modes"]:
            rule = _MODE_OBJECT_RULES[fn]
            self._emit(rule, node, observed=fn,
                       source_desc="API call",
                       sink_desc=f"{mod}.{fn}()",
                       evidence_type="ast_api_pattern", confidence="high",
                       signature=f"call:{mod}.{fn}",
                       rationale=f"Cipher mode object {fn}() selected in code.")
            return
        if fn in _CLASSICAL_CIPHER_RULES and mod.split(".")[-1:] == ["algorithms"]:
            rule = _CLASSICAL_CIPHER_RULES[fn]
            self._emit(rule, node, observed=fn,
                       source_desc="API call",
                       sink_desc=f"{mod}.{fn}",
                       evidence_type="ast_api_pattern", confidence="high",
                       signature=f"call:{mod}.{fn}",
                       rationale=f"Classical block cipher {fn} selected in code.")


def _analyze_file(path: str, metadata: dict, diagnostics: dict,
                  root: str | None = None) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, OSError, RecursionError):
        diagnostics["parser_failures"]["python"] = \
            diagnostics["parser_failures"].get("python", 0) + 1
        diagnostics.setdefault("parser_failure_files", []).append(
            evidence.relativize(path, root))
        return []
    diagnostics["files_analyzed"]["python"] = \
        diagnostics["files_analyzed"].get("python", 0) + 1

    flow = _Flow(path, metadata, root=root)
    flow.aliases = _collect_aliases(tree)
    flow._register_wrappers(tree)
    env: dict = {}
    try:
        flow._visit_block(tree.body, env)
    except RecursionError:
        diagnostics["parser_failures"]["python"] = \
            diagnostics["parser_failures"].get("python", 0) + 1
        return []
    diagnostics["unresolved_values"]["python"] = \
        diagnostics["unresolved_values"].get("python", 0) + flow.unresolved
    return flow.findings


def analyze_directory(target_directory: str, metadata: dict | None = None) -> dict:
    """Analyze all Python-family files under a directory."""
    from compliance import load_rule_metadata
    metadata = metadata if metadata is not None else load_rule_metadata()
    diagnostics: dict = {"parser_failures": {}, "files_analyzed": {},
                         "unresolved_values": {}, "parser_failure_files": [],
                         "engines": {}}
    findings: list[dict] = []
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for name in files:
            if os.path.splitext(name)[1].lower() not in _PYTHON_EXTS:
                continue
            findings.extend(_analyze_file(os.path.join(root, name), metadata,
                                          diagnostics, root=target_directory))
    diagnostics["engines"][ENGINE] = {
        "engine": ENGINE,
        "engine_version": evidence.ENGINE_VERSION,
        "language": LANGUAGE,
        "findings": len(findings),
    }
    return {"findings": findings, "diagnostics": diagnostics}
