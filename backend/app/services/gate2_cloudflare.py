from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import settings
from app.models import CoverageLedgerEntry
from app.services.event_bus import event_bus
from app.services.llm_providers import (
    EffectiveLLMConfig,
    IsolatedLLMSession,
    TokenUsage,
    estimate_tokens,
    max_input_tokens_for_budget,
)
from app.services.toolchain import find_git, find_node
from app.services.vault import scrub_secrets

STATIC_FALLBACK_BADGE = "Static Heuristic Fallback (No LLM)"

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".bla-hardened",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    "dist",
    "build",
    "out",
    "vendor",
    "target",
    ".mypy_cache",
    ".pytest_cache",
}

SOURCE_EXTS = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".rs",
    ".java",
    ".rb",
    ".php",
    ".sh",
    ".sql",
    ".yaml",
    ".yml",
}

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SECURITY_PATH_KEYWORDS = (
    "auth",
    "login",
    "jwt",
    "session",
    "oauth",
    "middleware",
    "route",
    "api",
    "controller",
    "handler",
    "sql",
    "query",
    "orm",
    "db",
    "database",
    "crypto",
    "hmac",
    "sign",
    "verify",
    "token",
    "secret",
    "exec",
    "shell",
    "subprocess",
    "spawn",
    "upload",
    "export",
    "file",
    "path",
    "admin",
    "rbac",
    "permission",
    "webhook",
    "payment",
    "billing",
    "server",
)

LOW_RISK_PATH_KEYWORDS = (
    "test",
    "spec",
    "mock",
    "fixture",
    "docs",
    "readme",
    "style",
    "theme",
    "constants",
    "types",
    "util",
    "format",
    "locale",
)

SECURITY_CONTENT_KEYWORDS = (
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "subprocess",
    "child_process",
    "os.system",
    "eval(",
    "pickle.loads",
    "yaml.load",
    "path.join",
    "os.path.join",
    "createHmac",
    "timingSafeEqual",
    "headers[",
    "innerHTML",
    "dangerouslySetInnerHTML",
    "rejectUnauthorized",
)


def encode_canonical_ref(value: str) -> str:
    """RFC3986 encoding matching Cloudflare validate-coverage-ledger.cjs encodeCanonicalRef."""
    out: list[str] = []
    for b in value.encode("utf-8"):
        unreserved = (
            (0x41 <= b <= 0x5A)
            or (0x61 <= b <= 0x7A)
            or (0x30 <= b <= 0x39)
            or b in (0x2D, 0x2E, 0x5F, 0x7E)
        )
        out.append(chr(b) if unreserved else f"%{b:02X}")
    return "".join(out)


def canonical_coverage_id(surface: str, boundary: str, subsystem: str, attack_class: str) -> str:
    return "::".join(
        encode_canonical_ref(v) for v in (surface, boundary, subsystem, attack_class)
    )


@dataclass
class AuditRule:
    rule_id: str
    title: str
    surface: str
    boundary: str
    attack_class: str
    companion_block: str
    pattern: re.Pattern[str]
    mitigation_pattern: re.Pattern[str]
    default_verdict: str
    likelihood: str
    impact: str
    overall_severity: str
    root_cause: str
    intended_behavior: str
    remediation_strategy: str
    fixed_code_hint: str
    attacker_perspective: str
    payloads: list[str]
    blocker_reason: str = ""
    local_plan: str = ""
    deployment_plan: str = ""


AUDIT_RULES: list[AuditRule] = [
    AuditRule(
        rule_id="path-traversal-uncontained-join",
        title="Uncontained filesystem path join from untrusted input",
        surface="filesystem-export",
        boundary="tenant-request-to-filesystem",
        attack_class="path-traversal",
        companion_block="DATA-ISOLATION-AND-LIFECYCLE.md",
        pattern=re.compile(r"(?:path\.join|os\.path\.join)\s*\([^)]*(?:req|request|file|filename|name|requested|param|query|input)[^)]*\)", re.IGNORECASE),
        mitigation_pattern=re.compile(r"(?:startsWith\s*\(|commonpath|realpath|is_relative_to|safe_join|path\.basename\s*\()", re.IGNORECASE),
        default_verdict="confirmed",
        likelihood="high",
        impact="high",
        overall_severity="high",
        root_cause="User-controlled path segment is joined directly into a filesystem base directory without canonical path resolution and prefix containment verification.",
        intended_behavior="Resolved file paths must remain strictly contained within the tenant's designated base directory.",
        remediation_strategy="Resolve the target path canonically with path.resolve / Path.resolve() and assert that it begins with the canonical base directory plus a path separator before any filesystem read.",
        fixed_code_hint="const baseDir = path.resolve(DATA_DIR, tenantId);\nconst resolved = path.resolve(baseDir, path.basename(requestedName));\nif (!resolved.startsWith(baseDir + path.sep)) throw new Error('Invalid export path');",
        attacker_perspective="Untrusted tenant caller supplying traversal segments in the file query parameter.",
        payloads=["../../etc/passwd", "../other-tenant/billing.csv"],
    ),
    AuditRule(
        rule_id="sql-string-interpolation",
        title="SQL query constructed via direct string interpolation",
        surface="database-query",
        boundary="untrusted-input-to-sql-sink",
        attack_class="sql-injection",
        companion_block="WEB-PROTOCOL-AND-AUTH.md",
        pattern=re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(?:\$\{[^}]+\}|f['\"][^\n]*\{[^}]+\}|['\"]\s*\+\s*[a-zA-Z_])", re.IGNORECASE),
        mitigation_pattern=re.compile(r"(?:prepare\s*\(|bind_param|text\s*\([^)]*:|parameterized)", re.IGNORECASE),
        default_verdict="confirmed",
        likelihood="high",
        impact="critical",
        overall_severity="high",
        root_cause="Dynamic request or caller parameters are interpolated directly into SQL syntax instead of using bound query parameters.",
        intended_behavior="All caller-supplied values must be bound as typed query parameters so SQL syntax cannot be altered.",
        remediation_strategy="Replace string interpolation with parameterized placeholders ($1/$2 or :param) and pass untrusted arguments in the parameter array.",
        fixed_code_hint="const sql = 'SELECT id, amount_cents, status FROM invoices WHERE tenant_id = $1 AND status = $2';\nreturn db.query(sql, [tenantId, statusFilter]);",
        attacker_perspective="Authenticated or unauthenticated API caller controlling status or tenant filter fields.",
        payloads=["' OR '1'='1", "paid' UNION SELECT 1,2,3 --"],
    ),
    AuditRule(
        rule_id="non-constant-time-hmac",
        title="Non-constant-time comparison on HMAC or webhook signature",
        surface="webhook-auth",
        boundary="external-webhook-to-verifier",
        attack_class="timing-side-channel",
        companion_block="WEB-PROTOCOL-AND-AUTH.md",
        pattern=re.compile(r"(?:signature|hmac|digest|mac|expected)\w*\s*(?:===|==|!==|!=)\s*(?:expected|signature|digest|mac|hmac)\w*", re.IGNORECASE),
        mitigation_pattern=re.compile(r"(?:timingSafeEqual|compare_digest|constant_time_compare)", re.IGNORECASE),
        default_verdict="confirmed",
        likelihood="low",
        impact="medium",
        overall_severity="medium",
        root_cause="Cryptographic signature verification uses standard string equality, leaking prefix match timing across network or local measurements.",
        intended_behavior="Cryptographic MAC and token comparisons must execute in constant time over equal-length byte buffers.",
        remediation_strategy="Convert both hex/byte digests to fixed-length Buffers and verify equality via crypto.timingSafeEqual (Node) or hmac.compare_digest (Python).",
        fixed_code_hint="const a = Buffer.from(signatureHeader, 'hex');\nconst b = Buffer.from(expected, 'hex');\nreturn a.length === b.length && crypto.timingSafeEqual(a, b);",
        attacker_perspective="External webhook sender measuring verification latency to forge HMAC digests.",
        payloads=["0000000000000000000000000000000000000000000000000000000000000000"],
    ),
    AuditRule(
        rule_id="command-injection-shell",
        title="Shell command invocation with dynamic input interpolation",
        surface="process-execution",
        boundary="application-to-os-shell",
        attack_class="command-injection",
        companion_block="DESKTOP-MOBILE-AND-LOCAL-IPC.md",
        pattern=re.compile(r"(?:child_process\.exec\s*\(|os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\([^)]*shell\s*=\s*True)", re.IGNORECASE),
        mitigation_pattern=re.compile(r"(?:execFile|shlex\.quote|shell\s*=\s*False)", re.IGNORECASE),
        default_verdict="confirmed",
        likelihood="medium",
        impact="critical",
        overall_severity="high",
        root_cause="Process invocation delegates command parsing to a system shell, allowing metacharacter injection if caller-controlled values reach the command string.",
        intended_behavior="External commands should be invoked via argument arrays with shell parsing disabled.",
        remediation_strategy="Use execFile / subprocess.run with an explicit argv list and shell=False, validating arguments against an allowlist.",
        fixed_code_hint="subprocess.run(['/usr/bin/tool', '--input', validated_arg], shell=False, check=True)",
        attacker_perspective="Caller injecting shell separators such as ';', '&&', or '$(...)'.",
        payloads=["; id", "$(whoami)"],
    ),
    AuditRule(
        rule_id="unsafe-code-eval",
        title="Dynamic code evaluation or unsafe deserialization sink",
        surface="runtime-deserialization",
        boundary="data-to-code-execution",
        attack_class="code-injection",
        companion_block="MEMORY-SAFETY-AND-BINARY.md",
        pattern=re.compile(r"(?:\beval\s*\(|new\s+Function\s*\(|pickle\.loads\s*\(|yaml\.load\s*\([^)]*\))", re.IGNORECASE),
        mitigation_pattern=re.compile(r"(?:yaml\.safe_load|SafeLoader|ast\.literal_eval)", re.IGNORECASE),
        default_verdict="confirmed",
        likelihood="medium",
        impact="critical",
        overall_severity="high",
        root_cause="Arbitrary code execution primitive invoked on potentially untrusted payload data.",
        intended_behavior="Data parsing must use inert data-only parsers such as JSON.parse or yaml.safe_load.",
        remediation_strategy="Eliminate eval / pickle.loads / unsafe yaml.load and switch to safe schema-validated parsing.",
        fixed_code_hint="data = yaml.safe_load(raw_payload)",
        attacker_perspective="Attacker providing crafted serialized or expression input.",
        payloads=["!!python/object/apply:os.system ['id']"],
    ),
    AuditRule(
        rule_id="unverified-tenant-header-trust",
        title="Tenant identity derived directly from mutable request header",
        surface="http-api",
        boundary="reverse-proxy-to-app-auth",
        attack_class="broken-access-control",
        companion_block="CLOUD-AND-DEPLOYMENT.md",
        pattern=re.compile(r"headers\[['\"]x-tenant-id['\"]\]|headers\.get\(['\"]x-tenant-id['\"]\)", re.IGNORECASE),
        mitigation_pattern=re.compile(r"(?:verifyJwt|authenticateRequest|requireAuth|jwt\.verify|session\.tenant)", re.IGNORECASE),
        default_verdict="needs_validation",
        likelihood="medium",
        impact="high",
        overall_severity="unrated",
        root_cause="Application reads x-tenant-id directly from incoming HTTP headers; whether an upstream gateway strips and injects this header authoritatively is not visible in repository source.",
        intended_behavior="Tenant identity must originate from a verified session or a trusted gateway boundary that strips spoofed client headers.",
        remediation_strategy="Verify gateway header stripping in deployment routing or bind tenant identity to a cryptographically signed JWT/session claim.",
        fixed_code_hint="const tenantId = req.authContext.verifiedTenantId;",
        attacker_perspective="External client sending a forged x-tenant-id header directly to the service.",
        payloads=["x-tenant-id: target-tenant"],
        blocker_reason="Upstream reverse-proxy header stripping and network ingress isolation policies are defined outside this repository.",
        local_plan="Start the server in an isolated loopback harness and send GET /api/exports with a spoofed x-tenant-id header to verify whether the app rejects unauthenticated header assertions.",
        deployment_plan="Inspect ingress / Cloudflare Access / reverse-proxy config to confirm external x-tenant-id headers are unconditionally stripped and overwritten by authenticated edge middleware.",
    ),
    AuditRule(
        rule_id="unsafe-dom-html-sink",
        title="Unescaped HTML rendering sink",
        surface="client-ui",
        boundary="data-to-dom-execution",
        attack_class="cross-site-scripting",
        companion_block="CLIENT-SIDE.md",
        pattern=re.compile(r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=)", re.IGNORECASE),
        mitigation_pattern=re.compile(r"(?:DOMPurify\.sanitize|sanitizeHtml)", re.IGNORECASE),
        default_verdict="needs_validation",
        likelihood="medium",
        impact="high",
        overall_severity="unrated",
        root_cause="Raw HTML sink detected without an adjacent sanitizer call; exploitability depends on whether the upstream string is strictly static or attacker-influenced.",
        intended_behavior="Render untrusted values as text nodes or sanitize HTML through DOMPurify with an explicit allowlist.",
        remediation_strategy="Avoid raw HTML injection or wrap values with DOMPurify.sanitize before DOM insertion.",
        fixed_code_hint="element.textContent = untrustedValue;",
        attacker_perspective="Attacker storing or reflecting HTML markup into rendered view.",
        payloads=["<img src=x onerror=alert(1)>"],
        blocker_reason="Upstream data origin and CSP enforcement headers are not fully determinable from this isolated sink.",
        local_plan="Trace all callers passing content into the HTML sink using a minimal component fixture.",
        deployment_plan="Verify Content-Security-Policy headers and upstream input sanitization at the API layer.",
    ),
    AuditRule(
        rule_id="tls-verification-disabled",
        title="TLS certificate validation disabled on outbound client",
        surface="outbound-transport",
        boundary="service-to-upstream-tls",
        attack_class="transport-security",
        companion_block="CLOUD-AND-DEPLOYMENT.md",
        pattern=re.compile(r"(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)", re.IGNORECASE),
        mitigation_pattern=re.compile(r"(?:ca_bundle|NODE_ENV\s*===\s*['\"]test['\"])", re.IGNORECASE),
        default_verdict="hardening_note",
        likelihood="low",
        impact="medium",
        overall_severity="low",
        root_cause="Outbound TLS verification appears disabled, exposing transport traffic to man-in-the-middle interception on untrusted networks.",
        intended_behavior="Enforce strict TLS certificate verification using system or pinned CA bundles.",
        remediation_strategy="Remove rejectUnauthorized: false / verify=False and provide an explicit trusted CA certificate if connecting to internal PKI.",
        fixed_code_hint="rejectUnauthorized: true",
        attacker_perspective="On-path network attacker intercepting outbound TLS handshakes.",
        payloads=["mitm-self-signed-cert"],
    ),
]


@dataclass
class CloudflareFindingData:
    fingerprint: str
    title: str
    description: str
    attack_class: str
    file_path: str
    line_number: int
    verdict: str
    severity: str
    confidence: str
    hunter_agent_id: str
    verifier_agent_id: str
    root_cause: str
    remediation: str
    fixed_code: str
    trace: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    blockers: list[str]
    schema_record: dict[str, Any] | None = None


@dataclass
class Gate2Result:
    status: str
    mode: str
    engine_badge: str
    duration_ms: int
    summary: str
    findings: list[CloudflareFindingData] = field(default_factory=list)
    ledger_units: list[dict[str, Any]] = field(default_factory=list)
    ledger_hashes: dict[str, str] = field(default_factory=dict)
    report_paths: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


def _discover_source_files(target_path: Path) -> list[Path]:
    discovered: list[Path] = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for fname in sorted(files):
            fpath = Path(root) / fname
            if fpath.suffix.lower() in SOURCE_EXTS:
                try:
                    if fpath.stat().st_size <= 512 * 1024:
                        discovered.append(fpath)
                except OSError:
                    continue
    return discovered[:250]


def _resolve_direct_local_imports(target_path: Path, changed_files: list[Path]) -> list[Path]:
    """Resolve 1-hop relative local imports from changed files for contextual analysis."""
    base = target_path.resolve()
    imported: list[Path] = []
    seen = {p.resolve() for p in changed_files}

    js_import_re = re.compile(r"""(?:from|require\s*\(|import\s*\()\s*['"](\.\.?/[^'"]+)['"]""")
    py_import_re = re.compile(r"""^\s*from\s+(\.+[A-Za-z0-9_.]*)\s+import\s+([A-Za-z0-9_,\s*]+)""", re.MULTILINE)

    for cf in changed_files:
        try:
            text_val = cf.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        parent = cf.parent

        for m in js_import_re.finditer(text_val):
            spec = m.group(1)
            raw_cand = (parent / spec).resolve()
            candidates = [
                raw_cand,
                *(raw_cand.with_suffix(ext) for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")),
                *(raw_cand / f"index{ext}" for ext in (".ts", ".tsx", ".js", ".jsx")),
            ]
            for c in candidates:
                try:
                    c.relative_to(base)
                except ValueError:
                    continue
                if c.is_file() and c.suffix.lower() in SOURCE_EXTS and c not in seen:
                    seen.add(c)
                    imported.append(c)
                    break

        if cf.suffix.lower() == ".py":
            for m in py_import_re.finditer(text_val):
                mod_spec = m.group(1)
                dots = len(mod_spec) - len(mod_spec.lstrip("."))
                rem = mod_spec.lstrip(".")
                anchor = parent
                for _ in range(max(0, dots - 1)):
                    anchor = anchor.parent
                if rem:
                    rel_parts = rem.split(".")
                    cand_file = (anchor / Path(*rel_parts)).with_suffix(".py").resolve()
                    cand_pkg = (anchor / Path(*rel_parts) / "__init__.py").resolve()
                    for c in (cand_file, cand_pkg):
                        try:
                            c.relative_to(base)
                        except ValueError:
                            continue
                        if c.is_file() and c not in seen:
                            seen.add(c)
                            imported.append(c)
                            break
                else:
                    names = [n.strip().split(" as ")[0].strip() for n in m.group(2).split(",")]
                    for name in names:
                        if not name or name == "*":
                            continue
                        cand = (anchor / f"{name}.py").resolve()
                        try:
                            cand.relative_to(base)
                        except ValueError:
                            continue
                        if cand.is_file() and cand not in seen:
                            seen.add(cand)
                            imported.append(cand)

    return imported


def _resolve_git_diff_scope(
    target_path: Path,
    all_files: list[Path],
    base_ref: str = "",
) -> tuple[list[Path], list[Path], list[Path], str]:
    git_bin = find_git()
    if not git_bin or not (target_path / ".git").exists():
        return all_files, [], [], "Target is not a Git repository; audited all discovered files."

    base = target_path.resolve()
    changed_rels: set[str] = set()
    used_ref = base_ref.strip()

    def _run_git(args: list[str]) -> tuple[int, list[str]]:
        proc = subprocess.run(
            [git_bin, "-C", str(base), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        lines = [ln.strip().replace("\\", "/") for ln in proc.stdout.splitlines() if ln.strip()]
        return proc.returncode, lines

    diff_ran = False
    if used_ref:
        rc, out = _run_git(["diff", "--name-only", f"{used_ref}...HEAD"])
        if rc != 0:
            rc, out = _run_git(["diff", "--name-only", used_ref, "HEAD"])
        if rc == 0:
            changed_rels.update(out)
            diff_ran = True
    else:
        rc, out = _run_git(["diff", "--name-only", "HEAD~1...HEAD"])
        if rc == 0:
            changed_rels.update(out)
            used_ref = "HEAD~1"
            diff_ran = True

    for extra_args in (
        ["diff", "--name-only"],
        ["diff", "--cached", "--name-only"],
        ["ls-files", "--others", "--exclude-standard"],
    ):
        rc, out = _run_git(extra_args)
        if rc == 0:
            changed_rels.update(out)

    all_by_rel = {f.resolve().relative_to(base).as_posix(): f for f in all_files}
    changed_paths = [all_by_rel[r] for r in sorted(changed_rels) if r in all_by_rel]

    if not changed_paths:
        if diff_ran:
            return [], [], all_files, f"Diff scope ({used_ref or 'working tree'}...HEAD): 0 changed source files."
        return all_files, [], [], "Diff scope requested on single-commit clean repo; audited full working tree."

    direct_imports = _resolve_direct_local_imports(target_path, changed_paths)
    in_scope_set = {p.resolve() for p in changed_paths} | {p.resolve() for p in direct_imports}
    in_scope = [f for f in all_files if f.resolve() in in_scope_set]
    out_of_scope = [f for f in all_files if f.resolve() not in in_scope_set]

    note = (
        f"Diff scope ({used_ref or 'local changes'}...HEAD): "
        f"{len(changed_paths)} changed file(s) + {len(direct_imports)} direct local import(s); "
        f"{len(out_of_scope)} unchanged file(s) marked out_of_scope."
    )
    return in_scope, direct_imports, out_of_scope, note


def _score_file_security_priority(target_path: Path, fpath: Path) -> tuple[int, int]:
    rel = fpath.resolve().relative_to(target_path.resolve()).as_posix().lower()
    score = 10
    for kw in SECURITY_PATH_KEYWORDS:
        if kw in rel:
            score += 12
    for kw in LOW_RISK_PATH_KEYWORDS:
        if kw in rel:
            score -= 6
    try:
        raw = fpath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        raw = ""
    for kw in SECURITY_CONTENT_KEYWORDS:
        if kw in raw:
            score += 5
    return score, estimate_tokens(raw) + 40


def _prioritize_and_budget_files(
    target_path: Path,
    candidate_files: list[Path],
    provider: str,
    max_budget_usd: float,
    hard_token_cap: int,
) -> tuple[list[Path], list[Path], int, int]:
    token_limit = max_input_tokens_for_budget(provider, max_budget_usd, hard_cap=hard_token_cap)
    scored: list[tuple[int, int, str, Path]] = []
    for fpath in candidate_files:
        rel = fpath.resolve().relative_to(target_path.resolve()).as_posix()
        prio, est_tok = _score_file_security_priority(target_path, fpath)
        scored.append((prio, est_tok, rel, fpath))

    scored.sort(key=lambda item: (-item[0], item[1], item[2]))

    included: list[Path] = []
    deferred: list[Path] = []
    used_tokens = 0

    for _prio, est_tok, _rel, fpath in scored:
        if included and (used_tokens + est_tok > token_limit):
            deferred.append(fpath)
            continue
        if not included and est_tok > token_limit and len(scored) > 1:
            included.append(fpath)
            used_tokens += min(est_tok, token_limit)
            continue
        included.append(fpath)
        used_tokens += est_tok

    return included, deferred, used_tokens, token_limit


def _hash_files(files: list[Path]) -> str:
    h = hashlib.sha256()
    for f in sorted(files):
        try:
            h.update(f.name.encode("utf-8"))
            h.update(f.read_bytes())
        except OSError:
            continue
    return h.hexdigest()[:24]


def _infer_scope_name(lines: list[str], line_idx: int) -> str:
    for idx in range(line_idx, max(-1, line_idx - 25), -1):
        line = lines[idx]
        m = re.search(r"(?:async\s+)?(?:function|def|func|fn)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
        if m:
            return m.group(1)
        m2 = re.search(r"(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\(", line)
        if m2:
            return m2.group(1)
    return "module-scope"


def _sanitize_slug(raw: str, fallback: str = "item") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._/-]+", "-", (raw or "").strip()).strip("-/")
    return cleaned[:96] or fallback


def _make_finding_fingerprint(rule_id: str, rel_path: str, scope: str) -> str:
    clean_rule = re.sub(r"[^A-Za-z0-9._-]+", "-", (rule_id or "rule").lower()).strip("-") or "rule"
    clean_path = re.sub(r"[^A-Za-z0-9._/-]+", "-", rel_path).strip("-") or "unknown"
    clean_scope = re.sub(r"[^A-Za-z0-9._-]+", "-", scope).strip("-") or "scope"
    return f"cf:{clean_rule}:{clean_path}:{clean_scope}"


def _load_cloudflare_rubric_excerpt(skill_dir: Path | None) -> str:
    if not skill_dir:
        return (
            "Find source-grounded vulnerabilities that cross a real trust boundary. "
            "Only confirmed findings receive severity; overall_severity cannot exceed impact. "
            "Candidates blocked by external deployment facts receive verdict='needs_validation' with no severity."
        )
    parts: list[str] = []
    for fname, limit in (("SKILL.md", 2200), ("ATTACK-CLASSES.md", 1600)):
        p = skill_dir / fname
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="ignore")[:limit]
            parts.append(f"--- {fname} ---\n{txt}")
    return "\n\n".join(parts)


def _read_numbered_slice(target_path: Path, rel_file: str, center_line: int, radius: int = 25) -> str:
    base = target_path.resolve()
    fpath = (base / rel_file).resolve()
    try:
        fpath.relative_to(base)
    except ValueError:
        return ""
    if not fpath.exists() or not fpath.is_file():
        return ""
    lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, center_line - radius)
    end = min(len(lines), center_line + radius)
    return "\n".join(f"{ln}: {lines[ln - 1]}" for ln in range(start, end + 1))


def _clamp_severity(overall: str, impact: str) -> str:
    ov = overall.lower() if overall.lower() in SEVERITY_RANK else "medium"
    imp = impact.lower() if impact.lower() in SEVERITY_RANK else "medium"
    if SEVERITY_RANK[ov] > SEVERITY_RANK[imp]:
        return imp
    return ov


def _sanitize_rel_path(target_path: Path, candidate_rel: str, valid_rels: set[str]) -> str:
    norm = (candidate_rel or "").replace("\\", "/").lstrip("./").strip()
    if norm in valid_rels:
        return norm
    matches = [r for r in valid_rels if r.endswith("/" + norm) or r == norm]
    if len(matches) == 1:
        return matches[0]
    return next(iter(sorted(valid_rels)), "package.json")


def _normalize_trace(
    raw_trace: Any,
    rel_file: str,
    line_num: int,
    scope: str,
    title: str,
    valid_rels: set[str],
    target_path: Path,
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    if isinstance(raw_trace, list):
        for item in raw_trace[:8]:
            if not isinstance(item, dict):
                continue
            fpath = _sanitize_rel_path(target_path, str(item.get("file") or rel_file), valid_rels)
            ln = max(1, int(item.get("line") or line_num))
            sc = str(item.get("scope") or scope).strip() or scope
            desc = str(item.get("description") or title).strip() or title
            steps.append({"kind": "propagation", "file": fpath, "line": ln, "scope": sc, "description": desc[:400]})

    dedup: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for s in steps:
        k = json.dumps([s["file"], s["line"], s["scope"], s["description"]])
        if k not in seen_keys:
            seen_keys.add(k)
            dedup.append(s)

    if not dedup:
        return [
            {
                "kind": "entrypoint",
                "file": rel_file,
                "line": max(1, line_num - 2),
                "scope": scope,
                "description": f"Untrusted input enters {scope}.",
            },
            {
                "kind": "sink",
                "file": rel_file,
                "line": max(1, line_num),
                "scope": scope,
                "description": f"Boundary sink reached for: {title}",
            },
        ]
    if len(dedup) == 1:
        dedup[0]["kind"] = "sink"
        return dedup
    dedup[0]["kind"] = "entrypoint"
    dedup[-1]["kind"] = "sink"
    for mid in dedup[1:-1]:
        mid["kind"] = "propagation"
    return dedup


def _append_unassigned_ledger_units(
    target_path: Path,
    files: list[Path],
    status: str,
    reason: str,
    ledger_units: list[dict[str, Any]],
    ledger_hashes: dict[str, str],
    prior_by_id: dict[str, CoverageLedgerEntry],
) -> None:
    if not files:
        return
    base = target_path.resolve()
    by_subsystem: dict[str, list[Path]] = {}
    for f in files:
        rel = f.resolve().relative_to(base).as_posix()
        sub = rel.split("/")[0] if "/" in rel else "root"
        by_subsystem.setdefault(sub, []).append(f)

    for sub, sub_files in sorted(by_subsystem.items()):
        rels = sorted(f.resolve().relative_to(base).as_posix() for f in sub_files)[:20]
        surface = "budget-deferred-source" if status == "deferred" else "unchanged-repository-source"
        boundary = "budget-cap" if status == "deferred" else "diff-scope-boundary"
        attack_class = "deferred-low-priority" if status == "deferred" else "out-of-scope"
        cov_id = canonical_coverage_id(surface, boundary, sub, attack_class)
        if cov_id in ledger_hashes:
            continue
        ledger_hashes[cov_id] = _hash_files(sub_files)
        prior = prior_by_id.get(cov_id)
        prior_status = "new" if prior is None else ("prior_deferred" if status == "deferred" else "prior_out_of_scope")
        ledger_units.append({
            "coverage_id": cov_id,
            "canonical_refs": {
                "surface": surface,
                "boundary": boundary,
                "subsystem": sub,
                "attack_class": attack_class,
            },
            "surface": surface,
            "boundary": boundary,
            "subsystem": sub,
            "attack_class": attack_class,
            "starting_paths": rels,
            "ordinary_attack_class_block": None,
            "selected_companion_blocks": [],
            "excluded_blocks": [],
            "prior_status": prior_status,
            "attempts": [],
            "wave": 1,
            "status": status,
            "agent_id": None,
            "reviewed_paths": [],
            "local_checks": [],
            "result_fingerprints": [],
            "unresolved": [reason],
        })


def _run_dual_session_llm_audit(
    run_id: str,
    target_path: Path,
    included_files: list[Path],
    skill_dir: Path | None,
    llm_config: EffectiveLLMConfig,
    prior_by_id: dict[str, CoverageLedgerEntry],
    audit_profile: str,
    max_budget_usd: float,
    token_limit: int,
) -> tuple[list[CloudflareFindingData], list[dict[str, Any]], list[dict[str, Any]], dict[str, str], TokenUsage]:
    rubric = _load_cloudflare_rubric_excerpt(skill_dir)
    valid_rels = {f.resolve().relative_to(target_path.resolve()).as_posix() for f in included_files}
    rel_list = sorted(valid_rels)
    total_usage = TokenUsage()

    code_bundle_parts: list[str] = []
    max_bundle_chars = min(44000, max(1200, token_limit * 4))
    total_chars = 0
    for sf in included_files:
        rel = sf.resolve().relative_to(target_path.resolve()).as_posix()
        raw = sf.read_text(encoding="utf-8", errors="replace")
        numbered = "\n".join(f"{i + 1}: {ln}" for i, ln in enumerate(raw.splitlines()[:260]))
        chunk = f"=== FILE: {rel} ===\n{numbered}\n"
        if code_bundle_parts and total_chars + len(chunk) > max_bundle_chars:
            break
        code_bundle_parts.append(chunk[:max_bundle_chars])
        total_chars += len(chunk)

    hunter_id = "llm-hunter-sa-001"
    event_bus.emit_log(
        run_id,
        2,
        f"Session A [{hunter_id}]: Launching isolated Hunter LLM pass ({llm_config.provider}/{llm_config.resolved_model}) over {len(code_bundle_parts)} prioritized file(s)...",
        "info",
    )

    hunter_system = (
        "You are Session A (Hunter) in a Cloudflare security-audit-skill review. "
        "Identify concrete, source-grounded candidate vulnerabilities crossing real trust boundaries. "
        "Do NOT confirm findings yourself — emit candidate hypotheses for independent Session B verification.\n\n"
        f"{rubric}\n\n"
        "Respond strictly with JSON:\n"
        '{"candidates": [{"rule_id": "slug", "title": "...", "surface": "slug", "boundary": "slug", '
        '"attack_class": "slug", "file": "exact/relative/path", "line": 12, "scope": "functionName", '
        '"claimed_root_cause": "...", "intended_behavior": "...", "proposed_verdict": "confirmed|needs_validation|hardening_note", '
        '"trace": [{"file": "...", "line": 10, "scope": "...", "description": "..."}], '
        '"attacker_perspective": "...", "payloads": ["..."], "remediation_hint": "...", "fixed_code": "..."}]}'
    )
    hunter_user = (
        f"Audit profile: {audit_profile}\n"
        f"Repository files ({len(code_bundle_parts)}):\n\n"
        + "\n".join(code_bundle_parts)
    )

    session_a = IsolatedLLMSession(llm_config)
    hunter_raw, usage_a = session_a.complete_json_with_usage(
        system_prompt=hunter_system,
        user_prompt=hunter_user,
        max_tokens=3200,
        schema_hint='{"candidates": [ ... ]}',
    )
    total_usage.add(usage_a)
    raw_candidates = hunter_raw.get("candidates") if isinstance(hunter_raw, dict) else hunter_raw
    if not isinstance(raw_candidates, list):
        raw_candidates = []

    event_bus.emit_log(
        run_id,
        2,
        f"Session A [{hunter_id}] proposed {len(raw_candidates)} candidate(s) "
        f"(tokens: in={usage_a.prompt_tokens}, out={usage_a.completion_tokens}, est=${usage_a.estimated_cost_usd:.4f}). "
        "Starting isolated Session B Verifier calls (zero Hunter CoT shared)...",
        "info",
    )

    verifier_system = (
        "You are Session B (Independent Verifier) in a Cloudflare security-audit-skill review. "
        "You did NOT write this candidate and have NO access to Hunter reasoning. "
        "Try to REFUTE the hypothesis using ONLY the raw source code slice provided.\n"
        "- Return decision='rejected' with a concrete 'reason' if mitigating controls exist or no real trust boundary is crossed.\n"
        "- Return decision='needs_validation' (NO severity) with exact 'blockers' and 'validation_plan' (local/deployment) if a decisive runtime/gateway/config fact is outside source.\n"
        "- Return decision='confirmed' ONLY if the boundary violation is provably present in source, with realistic likelihood, impact, overall_severity (<= impact), confidence, execution, and smallest remediation.\n"
        "Respond strictly with JSON:\n"
        '{"decision": "confirmed|needs_validation|rejected|hardening_note", "title": "...", "description": "...", '
        '"root_cause": "...", "intended_behavior": "...", "likelihood": "low|medium|high|critical", "likelihood_reason": "...", '
        '"impact": "low|medium|high|critical", "impact_reason": "...", "overall_severity": "informational|low|medium|high|critical", '
        '"confidence": "low|medium|high", "confidence_reason": "...", "observed_result": "...", '
        '"remediation_strategy": "...", "fixed_code": "...", "blockers": ["..."], "local_plan": "...", "deployment_plan": "...", "reason": "..."}'
    )

    findings_list: list[CloudflareFindingData] = []
    schema_findings: list[dict[str, Any]] = []
    ledger_units: list[dict[str, Any]] = []
    ledger_hashes: dict[str, str] = {}
    seen_fps: set[str] = set()
    unit_hash = _hash_files(included_files)
    verifier_seq = 0

    for cand in raw_candidates[:16]:
        if not isinstance(cand, dict) or event_bus.is_cancelled(run_id):
            continue
        if max_budget_usd > 0 and total_usage.estimated_cost_usd >= max_budget_usd:
            event_bus.emit_log(
                run_id,
                2,
                f"Budget cap reached (${total_usage.estimated_cost_usd:.4f} >= ${max_budget_usd:.2f}); stopping further verifier calls cleanly.",
                "warn",
            )
            break

        rel_file = _sanitize_rel_path(target_path, str(cand.get("file") or ""), valid_rels)
        line_num = max(1, int(cand.get("line") or 1))
        scope = str(cand.get("scope") or "module-scope").strip() or "module-scope"
        rule_id = _sanitize_slug(str(cand.get("rule_id") or cand.get("attack_class") or "llm-finding"), "llm-finding")
        fp = _make_finding_fingerprint(rule_id, rel_file, scope)
        if fp in seen_fps:
            continue
        seen_fps.add(fp)

        verifier_seq += 1
        verifier_id = f"llm-verifier-sb-{verifier_seq:03d}"
        raw_slice = _read_numbered_slice(target_path, rel_file, line_num, radius=25)
        minimal_claim = {
            "fingerprint": fp,
            "title": str(cand.get("title") or rule_id),
            "file": rel_file,
            "line": line_num,
            "scope": scope,
            "attack_class": str(cand.get("attack_class") or rule_id),
            "boundary": str(cand.get("boundary") or "application-boundary"),
            "claimed_root_cause": str(cand.get("claimed_root_cause") or "Potential trust boundary violation."),
        }
        verifier_user = (
            "HYPOTHESIS CLAIM (untrusted — attempt to refute):\n"
            f"{json.dumps(minimal_claim, indent=2)}\n\n"
            f"RAW SOURCE SLICE ({rel_file} around line {line_num}):\n"
            f"{raw_slice or '(file unreadable)'}"
        )

        session_b = IsolatedLLMSession(llm_config)
        v_out, usage_b = session_b.complete_json_with_usage(
            system_prompt=verifier_system,
            user_prompt=verifier_user,
            max_tokens=1600,
            schema_hint='{"decision": "confirmed|needs_validation|rejected|hardening_note", ...}',
        )
        total_usage.add(usage_b)
        if not isinstance(v_out, dict):
            continue

        decision = str(v_out.get("decision") or "needs_validation").strip().lower()
        if decision not in ("confirmed", "needs_validation", "rejected", "hardening_note"):
            decision = "needs_validation"

        title = str(v_out.get("title") or minimal_claim["title"]).strip() or minimal_claim["title"]
        desc = str(v_out.get("description") or minimal_claim["claimed_root_cause"]).strip() or title
        root_cause = str(v_out.get("root_cause") or minimal_claim["claimed_root_cause"]).strip() or desc
        intended = str(v_out.get("intended_behavior") or cand.get("intended_behavior") or "Enforce trust boundary invariants.").strip()
        remediation = str(v_out.get("remediation_strategy") or cand.get("remediation_hint") or "Enforce strict validation at the trust boundary.").strip()
        fixed_code = str(v_out.get("fixed_code") or cand.get("fixed_code") or "").strip()

        trace = _normalize_trace(cand.get("trace"), rel_file, line_num, scope, title, valid_rels, target_path)
        evidence = [
            {
                "file": rel_file,
                "line": line_num,
                "description": f"Independently verified by {verifier_id} on raw source slice at {rel_file}:{line_num}.",
            }
        ]

        surface = _sanitize_slug(str(cand.get("surface") or "application"), "application")
        boundary = _sanitize_slug(str(cand.get("boundary") or "trust-boundary"), "trust-boundary")
        attack_class = _sanitize_slug(str(cand.get("attack_class") or rule_id), "security-defect")
        subsystem = "profile/quick/all-in-scope-subsystems" if audit_profile == "quick" else (rel_file.split("/")[0] if "/" in rel_file else "root")

        schema_rec: dict[str, Any] | None = None
        blockers: list[str] = []
        severity = "unrated"
        confidence = str(v_out.get("confidence") or "medium").lower()
        if confidence not in ("low", "medium", "high"):
            confidence = "medium"

        if decision == "confirmed":
            lik = str(v_out.get("likelihood") or "medium").lower()
            if lik not in SEVERITY_RANK:
                lik = "medium"
            imp = str(v_out.get("impact") or "high").lower()
            if imp not in SEVERITY_RANK:
                imp = "high"
            severity = _clamp_severity(str(v_out.get("overall_severity") or imp), imp)
            payloads = cand.get("payloads")
            if not isinstance(payloads, list) or not payloads:
                payloads = ["boundary-test-input"]
            payloads = [str(p) for p in dict.fromkeys(payloads) if str(p).strip()][:5] or ["boundary-test-input"]

            code_changes = [{"file_name": rel_file, "fixed_code": fixed_code}] if fixed_code else []
            schema_rec = {
                "verdict": "confirmed",
                "fingerprint": fp,
                "title": title,
                "description": desc,
                "root_cause": root_cause,
                "intended_behavior": intended,
                "trace": trace,
                "evidence": evidence,
                "conditions": [
                    {
                        "kind": "system_configuration",
                        "description": f"Reachable across {boundary} in reviewed repository source.",
                    }
                ],
                "execution": {
                    "attacker_perspective": str(cand.get("attacker_perspective") or "Untrusted caller across boundary.").strip() or "Untrusted caller.",
                    "payloads": payloads,
                    "instructions": [
                        f"Inspect {rel_file}:{line_num} in scope {scope}.",
                        "Exercise the boundary using an isolated local test fixture.",
                    ],
                    "observed_result": str(v_out.get("observed_result") or f"Trust boundary {boundary} violated at {rel_file}:{line_num}.").strip(),
                },
                "remediation": (
                    {"strategy": remediation, "code_changes": code_changes}
                    if code_changes
                    else {"strategy": remediation}
                ),
                "severity": {
                    "likelihood": {"score": lik, "reason": str(v_out.get("likelihood_reason") or "Reachable from untrusted input.").strip()},
                    "impact": {"score": imp, "reason": str(v_out.get("impact_reason") or "Crosses security boundary.").strip()},
                    "overall_severity": severity,
                },
                "confidence": {
                    "score": confidence,
                    "reason": str(v_out.get("confidence_reason") or f"Independently confirmed by {verifier_id} without Session A context.").strip(),
                },
            }
            schema_findings.append(schema_rec)
            event_bus.emit_log(
                run_id,
                2,
                f"Session B [{verifier_id}] CONFIRMED ({severity.upper()}): {title} at {rel_file}:{line_num}",
                "error" if severity in ("critical", "high") else "warn",
            )
        elif decision == "needs_validation":
            raw_blockers = v_out.get("blockers")
            if isinstance(raw_blockers, list) and raw_blockers:
                blockers = [str(b).strip() for b in dict.fromkeys(raw_blockers) if str(b).strip()]
            if not blockers:
                blockers = ["External runtime or deployment control is not observable in repository source."]
            val_plan: dict[str, str] = {}
            if str(v_out.get("local_plan") or "").strip():
                val_plan["local"] = str(v_out["local_plan"]).strip()
            if str(v_out.get("deployment_plan") or "").strip():
                val_plan["deployment"] = str(v_out["deployment_plan"]).strip()
            if not val_plan:
                val_plan["local"] = f"Validate {scope} in {rel_file}:{line_num} using an isolated loopback harness."

            schema_rec = {
                "verdict": "needs_validation",
                "fingerprint": fp,
                "title": title,
                "description": desc,
                "claimed_root_cause": root_cause,
                "trace": trace,
                "evidence": evidence,
                "blockers": blockers,
                "validation_plan": val_plan,
            }
            schema_findings.append(schema_rec)
            event_bus.emit_log(
                run_id,
                2,
                f"Session B [{verifier_id}] NEEDS VALIDATION (unrated): {title} at {rel_file}:{line_num}",
                "warn",
            )
        elif decision == "rejected":
            reason = str(v_out.get("reason") or "Refuted by independent source review in Session B.").strip()
            schema_rec = {
                "verdict": "rejected",
                "fingerprint": fp,
                "title": title,
                "description": desc,
                "claimed_root_cause": root_cause,
                "trace": trace,
                "evidence": evidence,
                "reason": reason,
            }
            schema_findings.append(schema_rec)
            event_bus.emit_log(
                run_id,
                2,
                f"Session B [{verifier_id}] REJECTED candidate {fp}: {reason[:140]}",
                "info",
            )
            continue
        else:
            severity = "low"
            event_bus.emit_log(
                run_id,
                2,
                f"Session B [{verifier_id}] HARDENING NOTE: {title} at {rel_file}:{line_num}",
                "info",
            )

        findings_list.append(
            CloudflareFindingData(
                fingerprint=fp,
                title=title,
                description=desc,
                attack_class=attack_class,
                file_path=rel_file,
                line_number=line_num,
                verdict=decision,
                severity=severity,
                confidence=confidence,
                hunter_agent_id=hunter_id,
                verifier_agent_id=verifier_id,
                root_cause=root_cause,
                remediation=remediation,
                fixed_code=fixed_code,
                trace=trace,
                evidence=evidence,
                blockers=blockers,
                schema_record=schema_rec,
            )
        )

        cov_id = canonical_coverage_id(surface, boundary, subsystem, attack_class)
        if cov_id not in ledger_hashes:
            ledger_hashes[cov_id] = unit_hash
            prior = prior_by_id.get(cov_id)
            prior_status = (
                "new"
                if prior is None
                else ("prior_confirmed_same_source" if prior.source_hash == unit_hash else "prior_confirmed_changed_source")
            )
            is_candidate = decision in ("confirmed", "needs_validation")
            ledger_units.append({
                "coverage_id": cov_id,
                "canonical_refs": {
                    "surface": surface,
                    "boundary": boundary,
                    "subsystem": subsystem,
                    "attack_class": attack_class,
                },
                "surface": surface,
                "boundary": boundary,
                "subsystem": subsystem,
                "attack_class": attack_class,
                "starting_paths": [rel_file],
                "ordinary_attack_class_block": attack_class,
                "selected_companion_blocks": ["ATTACK-CLASSES.md"],
                "excluded_blocks": [],
                "prior_status": prior_status,
                "attempts": [],
                "wave": 1,
                "status": "candidate" if is_candidate else "covered",
                "agent_id": hunter_id,
                "reviewed_paths": [rel_file],
                "local_checks": [
                    {
                        "agent_id": hunter_id,
                        "reviewed_paths": [rel_file],
                        "invariant": f"Session A hunt on {boundary} ({attack_class}).",
                        "method": "source",
                        "result": f"Proposed candidate {fp}.",
                        "artifact": None,
                    },
                    {
                        "agent_id": verifier_id,
                        "reviewed_paths": [rel_file],
                        "invariant": f"Session B independent verification of {fp} (isolated from Session A CoT).",
                        "method": "source",
                        "result": f"Independent verdict: {decision}.",
                        "artifact": None,
                    },
                ],
                "result_fingerprints": [fp] if is_candidate else [],
                "unresolved": [],
            })

    if not ledger_units and rel_list:
        base_paths = rel_list[:10]
        cov_id = canonical_coverage_id("repository-source", "all-trust-boundaries", "root", "general-security-review")
        ledger_hashes[cov_id] = unit_hash
        prior = prior_by_id.get(cov_id)
        ledger_units.append({
            "coverage_id": cov_id,
            "canonical_refs": {
                "surface": "repository-source",
                "boundary": "all-trust-boundaries",
                "subsystem": "root",
                "attack_class": "general-security-review",
            },
            "surface": "repository-source",
            "boundary": "all-trust-boundaries",
            "subsystem": "root",
            "attack_class": "general-security-review",
            "starting_paths": base_paths,
            "ordinary_attack_class_block": "general-security-review",
            "selected_companion_blocks": ["ATTACK-CLASSES.md"],
            "excluded_blocks": [],
            "prior_status": "new" if prior is None else ("prior_covered_same_source" if prior.source_hash == unit_hash else "prior_covered_changed_source"),
            "attempts": [],
            "wave": 1,
            "status": "covered",
            "agent_id": hunter_id,
            "reviewed_paths": base_paths,
            "local_checks": [
                {
                    "agent_id": hunter_id,
                    "reviewed_paths": base_paths,
                    "invariant": "Verify repository source against Cloudflare security-audit-skill trust boundaries.",
                    "method": "source",
                    "result": "Session A found zero candidate boundary violations.",
                    "artifact": None,
                }
            ],
            "result_fingerprints": [],
            "unresolved": [],
        })

    return findings_list, schema_findings, ledger_units, ledger_hashes, total_usage


def _run_cloudflare_node_validator(
    skill_dir: Path | None,
    validator_filename: str,
    json_path: Path,
) -> tuple[bool, str]:
    node = find_node()
    if not skill_dir or not node:
        return False, "Cloudflare validator or Node.js unavailable"
    script_path = skill_dir / validator_filename
    if not script_path.exists():
        return False, f"Missing {validator_filename}"

    if os.name != "nt":
        proc = subprocess.run(
            [node, str(script_path), str(json_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        msg = (proc.stdout or proc.stderr or "").strip()
        return proc.returncode == 0, msg

    schema_path = skill_dir / "report-schema.json"
    inline_js = (
        "const fs=require('node:fs');"
        "const mod=require(process.argv[1]);"
        "const doc=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));"
        "const isFindings=process.argv[3]==='validate-findings.cjs';"
        "const errs=isFindings"
        "?mod.validateDocument(doc,JSON.parse(fs.readFileSync(process.argv[4],'utf8')))"
        ":mod.validateDocument(doc);"
        "if(errs.length>0){for(const e of errs)console.error('ERROR:',e);process.exit(1);}"
        "console.log('PASS: '+doc.length+' record(s) validated via '+process.argv[3]);"
    )
    proc = subprocess.run(
        [node, "-e", inline_js, str(script_path), str(json_path), validator_filename, str(schema_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    msg = (proc.stdout or proc.stderr or "").strip()
    return proc.returncode == 0, msg


def parse_cloudflare_markdown_reports(report_dir: Path) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    detail_md = report_dir / "FINDINGS-DETAIL.md"
    needs_md = report_dir / "NEEDS-VALIDATION.md"
    report_md = report_dir / "REPORT.md"

    def _extract_sections(md_text: str, verdict: str) -> None:
        blocks = re.split(r"(?m)^###\s+", md_text)
        for block in blocks[1:]:
            lines = block.strip().splitlines()
            if not lines:
                continue
            header = lines[0].strip()
            body = "\n".join(lines[1:])
            fp_m = re.search(r"\*\*Fingerprint:\*\*\s*`([^`]+)`", body)
            sev_m = re.search(r"\*\*Severity:\*\*\s*`?([a-zA-Z]+)`?", body)
            loc_m = re.search(r"\*\*Location:\*\*\s*`([^:`]+):(\d+)`", body)
            parsed.append({
                "title": header,
                "verdict": verdict,
                "fingerprint": fp_m.group(1) if fp_m else f"md:{verdict}:{hashlib.sha1(header.encode()).hexdigest()[:10]}",
                "severity": sev_m.group(1).lower() if sev_m else ("unrated" if verdict == "needs_validation" else "low"),
                "file_path": loc_m.group(1) if loc_m else "unknown",
                "line_number": int(loc_m.group(2)) if loc_m else 1,
            })

    if detail_md.exists():
        _extract_sections(detail_md.read_text(encoding="utf-8", errors="ignore"), "confirmed")
    if needs_md.exists():
        _extract_sections(needs_md.read_text(encoding="utf-8", errors="ignore"), "needs_validation")
    if report_md.exists():
        text_val = report_md.read_text(encoding="utf-8", errors="ignore")
        if "## Hardening Notes" in text_val:
            tail = text_val.split("## Hardening Notes", 1)[1].split("\n## ", 1)[0]
            for line in tail.splitlines():
                m = re.match(r"^\-\s+\*\*([^*]+)\*\*\s*\(`([^:`]+):(\d+)`\):\s*(.+)$", line.strip())
                if m:
                    parsed.append({
                        "title": m.group(1),
                        "verdict": "hardening_note",
                        "fingerprint": f"md:hardening:{hashlib.sha1(m.group(1).encode()).hexdigest()[:10]}",
                        "severity": "low",
                        "file_path": m.group(2),
                        "line_number": int(m.group(3)),
                        "description": m.group(4),
                    })
    return parsed


def _write_cloudflare_reports(
    out_dir: Path,
    target_path: Path,
    profile: str,
    audit_scope: str,
    engine_badge: str,
    prior_ledger_count: int,
    findings: list[CloudflareFindingData],
    ledger_units: list[dict[str, Any]],
    usage: TokenUsage,
) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    confirmed = [f for f in findings if f.verdict == "confirmed"]
    needs_val = [f for f in findings if f.verdict == "needs_validation"]
    hardening = [f for f in findings if f.verdict == "hardening_note"]
    rejected = [f for f in findings if f.verdict == "rejected"]

    report_lines = [
        "# Security Audit Report",
        "",
        f"- **Target:** `{target_path}`",
        f"- **Profile / Scope:** `{profile}` / `{audit_scope}`",
        f"- **Analysis Mode:** `{engine_badge}`",
        f"- **Token Usage / Est. Cost:** `{usage.prompt_tokens} prompt + {usage.completion_tokens} completion` (`${usage.estimated_cost_usd:.4f}`)",
        f"- **Execution Policy:** `sandboxed-source-and-local-only`",
        f"- **Prior Ledger Units Loaded:** {prior_ledger_count} ({'additive carry-forward enabled' if prior_ledger_count else 'initial baseline run'})",
        f"- **Generated:** `{dt.datetime.now(dt.timezone.utc).isoformat()}`",
        "",
        "## Security Posture Summary",
        "",
        f"Evaluated {len(ledger_units)} coverage unit(s) using `{engine_badge}` with strict hunter-vs-verifier separation. "
        f"Identified {len(confirmed)} confirmed finding(s), {len(needs_val)} needs-validation lead(s), "
        f"{len(hardening)} hardening note(s), and {len(rejected)} refuted candidate(s).",
        "",
        "## Confirmed Findings",
        "",
    ]
    if confirmed:
        report_lines.extend([
            "| Severity | Title | Location | Hunter | Independent Verifier |",
            "| --- | --- | --- | --- | --- |",
        ])
        for f in confirmed:
            report_lines.append(
                f"| `{f.severity}` | {f.title} | `{f.file_path}:{f.line_number}` | `{f.hunter_agent_id}` | `{f.verifier_agent_id}` |"
            )
    else:
        report_lines.append("No confirmed trust-boundary vulnerabilities were identified in this pass.")

    report_lines.extend(["", "## NEEDS VALIDATION", ""])
    if needs_val:
        report_lines.extend(["| Title | Location | Blocker |", "| --- | --- | --- |"])
        for f in needs_val:
            blocker = f.blockers[0] if f.blockers else "Deployment context not present in source."
            report_lines.append(f"| {f.title} | `{f.file_path}:{f.line_number}` | {blocker} |")
    else:
        report_lines.append("No unresolved deployment-dependent leads.")

    report_lines.extend(["", "## Hardening Notes", ""])
    if hardening:
        for f in hardening:
            report_lines.append(f"- **{f.title}** (`{f.file_path}:{f.line_number}`): {f.description}")
    else:
        report_lines.append("No additional hardening notes recorded.")

    covered_cnt = sum(1 for u in ledger_units if u["status"] == "covered")
    cand_cnt = sum(1 for u in ledger_units if u["status"] == "candidate")
    def_cnt = sum(1 for u in ledger_units if u["status"] == "deferred")
    oos_cnt = sum(1 for u in ledger_units if u["status"] == "out_of_scope")
    report_lines.extend([
        "",
        "## Coverage Summary",
        "",
        f"- Total ledger units: **{len(ledger_units)}**",
        f"- Covered (clean): **{covered_cnt}**",
        f"- Candidate (verified/tracked): **{cand_cnt}**",
        f"- Deferred (budget cap): **{def_cnt}**",
        f"- Out of scope (diff mode): **{oos_cnt}**",
    ])
    report_path = out_dir / "REPORT.md"
    report_path.write_text(scrub_secrets("\n".join(report_lines)), encoding="utf-8")

    detail_lines = ["# Findings Detail (Confirmed)", ""]
    if confirmed:
        for f in confirmed:
            detail_lines.extend([
                f"### {f.title}",
                "",
                f"- **Fingerprint:** `{f.fingerprint}`",
                f"- **Severity:** `{f.severity}`",
                f"- **Location:** `{f.file_path}:{f.line_number}`",
                f"- **Hunter Agent:** `{f.hunter_agent_id}`",
                f"- **Independent Verifier:** `{f.verifier_agent_id}`",
                f"- **Root Cause:** {f.root_cause}",
                f"- **Remediation:** {f.remediation}",
                "",
            ])
    else:
        detail_lines.append("No confirmed findings.")
    detail_path = out_dir / "FINDINGS-DETAIL.md"
    detail_path.write_text(scrub_secrets("\n".join(detail_lines)), encoding="utf-8")

    nv_lines = ["# Needs Validation Leads (Unrated)", ""]
    if needs_val:
        for f in needs_val:
            nv_lines.extend([
                f"### {f.title}",
                "",
                f"- **Fingerprint:** `{f.fingerprint}`",
                f"- **Location:** `{f.file_path}:{f.line_number}`",
                f"- **Hunter Agent:** `{f.hunter_agent_id}`",
                f"- **Independent Verifier:** `{f.verifier_agent_id}`",
                f"- **Claimed Root Cause:** {f.root_cause}",
                f"- **Blockers:** {'; '.join(f.blockers)}",
                "",
            ])
    else:
        nv_lines.append("No unresolved leads requiring external validation.")
    nv_path = out_dir / "NEEDS-VALIDATION.md"
    nv_path.write_text(scrub_secrets("\n".join(nv_lines)), encoding="utf-8")

    return {
        "REPORT.md": str(report_path),
        "FINDINGS-DETAIL.md": str(detail_path),
        "NEEDS-VALIDATION.md": str(nv_path),
    }


def _run_static_heuristic_audit(
    run_id: str,
    target_path: Path,
    source_files: list[Path],
    prior_by_id: dict[str, CoverageLedgerEntry],
    audit_profile: str,
) -> tuple[list[CloudflareFindingData], list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    if not source_files:
        return [], [], [], {}

    subsystem_files: dict[str, list[Path]] = {}
    for sf in source_files:
        rel = sf.resolve().relative_to(target_path.resolve()).as_posix()
        parts = rel.split("/")
        subsystem = parts[0] if len(parts) > 1 else "root"
        subsystem_files.setdefault(subsystem, []).append(sf)

    findings_list: list[CloudflareFindingData] = []
    schema_findings: list[dict[str, Any]] = []
    ledger_units: list[dict[str, Any]] = []
    ledger_hashes: dict[str, str] = {}

    hunter_seq = 0
    verifier_seq = 0
    seen_fingerprints: set[str] = set()

    for subsystem, files in sorted(subsystem_files.items()):
        rel_paths = [
            f.resolve().relative_to(target_path.resolve()).as_posix()
            for f in files
        ] or ["package.json"]
        unit_hash = _hash_files(files)

        for rule in AUDIT_RULES:
            eff_subsystem = "profile/quick/all-in-scope-subsystems" if audit_profile == "quick" else subsystem
            cov_id = canonical_coverage_id(rule.surface, rule.boundary, eff_subsystem, rule.attack_class)
            if cov_id in ledger_hashes:
                continue
            ledger_hashes[cov_id] = unit_hash

            prior = prior_by_id.get(cov_id)
            if prior is None:
                prior_status = "new"
            elif prior.source_hash == unit_hash:
                prior_status = "prior_covered_same_source" if prior.status == "covered" else "prior_confirmed_same_source"
            else:
                prior_status = "prior_covered_changed_source" if prior.status == "covered" else "prior_confirmed_changed_source"

            hunter_seq += 1
            hunter_id = f"heuristic-hunter-{hunter_seq:03d}"

            unit_candidates: list[CloudflareFindingData] = []
            reviewed_files: list[str] = []

            for fpath in files:
                rel = fpath.resolve().relative_to(target_path.resolve()).as_posix()
                reviewed_files.append(rel)
                try:
                    raw_text = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                lines = raw_text.splitlines()
                for idx, line in enumerate(lines):
                    if not rule.pattern.search(line):
                        continue
                    lineno = idx + 1
                    scope = _infer_scope_name(lines, idx)
                    fp = _make_finding_fingerprint(rule.rule_id, rel, scope)
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)

                    verifier_seq += 1
                    verifier_id = f"heuristic-verifier-{verifier_seq:03d}"

                    window_start = max(0, idx - 12)
                    window_end = min(len(lines), idx + 12)
                    context_window = "\n".join(lines[window_start:window_end])
                    has_mitigation = bool(rule.mitigation_pattern.search(context_window))

                    trace = [
                        {
                            "kind": "entrypoint",
                            "file": rel,
                            "line": max(1, window_start + 1),
                            "scope": scope,
                            "description": f"Input enters {scope} across {rule.boundary} boundary.",
                        },
                        {
                            "kind": "sink",
                            "file": rel,
                            "line": lineno,
                            "scope": scope,
                            "description": f"Boundary operation at line {lineno}: {line.strip()[:140]}",
                        },
                    ]
                    evidence = [
                        {
                            "file": rel,
                            "line": lineno,
                            "description": f"Verified source statement: {line.strip()[:160]}",
                        }
                    ]

                    if has_mitigation:
                        schema_findings.append({
                            "verdict": "rejected",
                            "fingerprint": fp,
                            "title": rule.title,
                            "description": f"Heuristic candidate in {rel}:{lineno} refuted by visible mitigating control.",
                            "claimed_root_cause": rule.root_cause,
                            "trace": trace,
                            "evidence": evidence,
                            "reason": "Source context contains an explicit mitigating control.",
                        })
                        continue

                    verdict = rule.default_verdict
                    blockers: list[str] = []
                    schema_rec: dict[str, Any] | None = None

                    if verdict == "confirmed":
                        severity = rule.overall_severity
                        schema_rec = {
                            "verdict": "confirmed",
                            "fingerprint": fp,
                            "title": rule.title,
                            "description": f"{rule.title} in {rel}:{lineno} ({scope}).",
                            "root_cause": rule.root_cause,
                            "intended_behavior": rule.intended_behavior,
                            "trace": trace,
                            "evidence": evidence,
                            "conditions": [
                                {
                                    "kind": "system_configuration",
                                    "description": f"Reachable through {rule.surface} in default local configuration.",
                                }
                            ],
                            "execution": {
                                "attacker_perspective": rule.attacker_perspective,
                                "payloads": rule.payloads,
                                "instructions": [
                                    f"Inspect {rel}:{lineno} inside function {scope}.",
                                    f"Supply boundary fixture payload ({rule.payloads[0]}) inside an isolated local test harness.",
                                ],
                                "observed_result": f"Sink at {rel}:{lineno} processes unvalidated input without enforcing {rule.attack_class} containment.",
                            },
                            "remediation": {
                                "strategy": rule.remediation_strategy,
                                "code_changes": [{"file_name": rel, "fixed_code": rule.fixed_code_hint}],
                            },
                            "severity": {
                                "likelihood": {"score": rule.likelihood, "reason": f"Directly reachable in {scope} without compensating controls."},
                                "impact": {"score": rule.impact, "reason": f"Crosses {rule.boundary} trust boundary."},
                                "overall_severity": rule.overall_severity,
                            },
                            "confidence": {
                                "score": "high",
                                "reason": f"Static heuristic verification by {verifier_id} (separate from {hunter_id}).",
                            },
                        }
                        schema_findings.append(schema_rec)
                        event_bus.emit_log(
                            run_id,
                            2,
                            f"[CONFIRMED {severity.upper()}] {rule.title} at {rel}:{lineno} ({hunter_id} -> {verifier_id})",
                            "error" if severity in ("critical", "high") else "warn",
                        )
                    elif verdict == "needs_validation":
                        severity = "unrated"
                        blockers = [rule.blocker_reason or "External deployment/runtime control absent from repository source."]
                        schema_rec = {
                            "verdict": "needs_validation",
                            "fingerprint": fp,
                            "title": rule.title,
                            "description": f"{rule.title} at {rel}:{lineno} requires deployment verification.",
                            "claimed_root_cause": rule.root_cause,
                            "trace": trace,
                            "evidence": evidence,
                            "blockers": blockers,
                            "validation_plan": {
                                "local": rule.local_plan or f"Exercise {scope} in an isolated local harness with dummy principals.",
                                "deployment": rule.deployment_plan or "Verify external gateway/proxy policy enforces this boundary.",
                            },
                        }
                        schema_findings.append(schema_rec)
                        event_bus.emit_log(
                            run_id,
                            2,
                            f"[NEEDS VALIDATION] {rule.title} at {rel}:{lineno} (unrated)",
                            "warn",
                        )
                    else:
                        severity = "low"

                    cf_item = CloudflareFindingData(
                        fingerprint=fp,
                        title=rule.title,
                        description=rule.root_cause,
                        attack_class=rule.attack_class,
                        file_path=rel,
                        line_number=lineno,
                        verdict=verdict,
                        severity=severity,
                        confidence="high" if verdict == "confirmed" else "medium",
                        hunter_agent_id=hunter_id,
                        verifier_agent_id=verifier_id,
                        root_cause=rule.root_cause,
                        remediation=rule.remediation_strategy,
                        fixed_code=rule.fixed_code_hint,
                        trace=trace,
                        evidence=evidence,
                        blockers=blockers,
                        schema_record=schema_rec,
                    )
                    findings_list.append(cf_item)
                    if verdict in ("confirmed", "needs_validation"):
                        unit_candidates.append(cf_item)

            effective_reviewed = sorted(set(reviewed_files)) or [rel_paths[0]]
            local_checks: list[dict[str, Any]] = [
                {
                    "agent_id": hunter_id,
                    "reviewed_paths": effective_reviewed,
                    "invariant": f"Verify {rule.boundary} enforces {rule.attack_class} protection.",
                    "method": "source",
                    "result": (
                        f"Raised {len(unit_candidates)} candidate(s) for verification."
                        if unit_candidates
                        else "No boundary violation observed in reviewed source paths."
                    ),
                    "artifact": None,
                }
            ]
            for cand in unit_candidates:
                local_checks.append({
                    "agent_id": cand.verifier_agent_id,
                    "reviewed_paths": [cand.file_path],
                    "invariant": f"Verification of {cand.fingerprint}.",
                    "method": "source",
                    "result": f"Verifier verdict: {cand.verdict}.",
                    "artifact": None,
                })

            ledger_units.append({
                "coverage_id": cov_id,
                "canonical_refs": {
                    "surface": rule.surface,
                    "boundary": rule.boundary,
                    "subsystem": eff_subsystem,
                    "attack_class": rule.attack_class,
                },
                "surface": rule.surface,
                "boundary": rule.boundary,
                "subsystem": eff_subsystem,
                "attack_class": rule.attack_class,
                "starting_paths": sorted(set(rel_paths))[:20],
                "ordinary_attack_class_block": rule.attack_class,
                "selected_companion_blocks": [rule.companion_block],
                "excluded_blocks": [],
                "prior_status": prior_status,
                "attempts": [],
                "wave": 1,
                "status": "candidate" if unit_candidates else "covered",
                "agent_id": hunter_id,
                "reviewed_paths": effective_reviewed,
                "local_checks": local_checks,
                "result_fingerprints": sorted(c.fingerprint for c in unit_candidates),
                "unresolved": [],
            })

    return findings_list, schema_findings, ledger_units, ledger_hashes


def run_gate2_cloudflare(
    run_id: str,
    target_path: Path,
    run_output_dir: Path,
    prior_ledger: list[CoverageLedgerEntry],
    audit_profile: str = "standard",
    force_simulation: bool = False,
    llm_config: EffectiveLLMConfig | None = None,
    audit_scope: str = "full",
    base_ref: str = "",
    max_budget_usd: float | None = None,
) -> Gate2Result:
    start = time.perf_counter()
    skill_dir = None if force_simulation else settings.resolved_cloudflare_skill_dir
    cf_out_dir = run_output_dir / "cloudflare"
    cf_out_dir.mkdir(parents=True, exist_ok=True)

    prior_by_id = {entry.coverage_id: entry for entry in prior_ledger}
    all_source_files = _discover_source_files(target_path)
    effective_scope = audit_scope if audit_scope in ("diff", "full") else "full"
    effective_budget = float(
        max_budget_usd
        if max_budget_usd is not None
        else (llm_config.default_max_budget_usd if llm_config else settings.default_max_budget_usd)
    )

    if effective_scope == "diff":
        scoped_files, direct_imports, out_of_scope_files, scope_note = _resolve_git_diff_scope(
            target_path,
            all_source_files,
            base_ref=base_ref,
        )
    else:
        scoped_files = all_source_files
        direct_imports = []
        out_of_scope_files = []
        scope_note = f"Full repository scope: {len(all_source_files)} source file(s)."

    provider_for_budget = llm_config.provider if (llm_config and llm_config.is_configured) else "none"
    included_files, deferred_files, est_input_tokens, token_limit = _prioritize_and_budget_files(
        target_path=target_path,
        candidate_files=scoped_files,
        provider=provider_for_budget,
        max_budget_usd=effective_budget,
        hard_token_cap=settings.default_max_input_tokens,
    )

    llm_ready = bool(llm_config and llm_config.is_configured and not force_simulation)
    llm_error: str | None = None
    usage = TokenUsage()

    event_bus.emit_log(
        run_id,
        2,
        f"Phase 1 (Scope & Budget): {scope_note} Pre-flight estimate: ~{est_input_tokens} input tokens "
        f"(cap={token_limit} tokens / ${effective_budget:.2f}); prioritized={len(included_files)}, deferred={len(deferred_files)}.",
        "info",
    )

    if llm_ready and llm_config is not None:
        mode = "live_llm"
        engine_badge = llm_config.active_badge
        event_bus.emit_log(
            run_id,
            2,
            f"Starting Gate 2: Adversarial Source Audit [{engine_badge} | profile={audit_profile}, scope={effective_scope}]",
            "info",
        )
        try:
            if included_files:
                findings_list, schema_findings, ledger_units, ledger_hashes, usage = _run_dual_session_llm_audit(
                    run_id=run_id,
                    target_path=target_path,
                    included_files=included_files,
                    skill_dir=skill_dir,
                    llm_config=llm_config,
                    prior_by_id=prior_by_id,
                    audit_profile=audit_profile,
                    max_budget_usd=effective_budget,
                    token_limit=token_limit,
                )
            else:
                findings_list, schema_findings, ledger_units, ledger_hashes = [], [], [], {}
            event_bus.emit_log(
                run_id,
                2,
                f"LLM telemetry: prompt_tokens={usage.prompt_tokens}, completion_tokens={usage.completion_tokens}, "
                f"estimated_cost_usd=${usage.estimated_cost_usd:.4f} (budget=${effective_budget:.2f}).",
                "info",
            )
        except Exception as exc:
            llm_error = scrub_secrets(str(exc))[:240]
            mode = "static_heuristic"
            engine_badge = STATIC_FALLBACK_BADGE
            event_bus.emit_log(
                run_id,
                2,
                f"LLM session failed ({llm_error}). Falling back cleanly to {STATIC_FALLBACK_BADGE}.",
                "warn",
            )
            findings_list, schema_findings, ledger_units, ledger_hashes = _run_static_heuristic_audit(
                run_id=run_id,
                target_path=target_path,
                source_files=included_files,
                prior_by_id=prior_by_id,
                audit_profile=audit_profile,
            )
    else:
        mode = "static_heuristic" if not force_simulation else "simulation"
        engine_badge = STATIC_FALLBACK_BADGE
        event_bus.emit_log(
            run_id,
            2,
            f"Starting Gate 2: Adversarial Source Audit [{engine_badge} | profile={audit_profile}, scope={effective_scope}]",
            "warn",
        )
        event_bus.emit_log(
            run_id,
            2,
            "No BYOK LLM provider configured (Gemini, Claude, OpenAI, or Ollama). Running Static Heuristic Fallback — configure a provider in Settings for live multi-agent AI auditing.",
            "warn",
        )
        findings_list, schema_findings, ledger_units, ledger_hashes = _run_static_heuristic_audit(
            run_id=run_id,
            target_path=target_path,
            source_files=included_files,
            prior_by_id=prior_by_id,
            audit_profile=audit_profile,
        )

    if event_bus.is_cancelled(run_id):
        return Gate2Result(
            status="aborted",
            mode=mode,
            engine_badge=engine_badge,
            duration_ms=int((time.perf_counter() - start) * 1000),
            summary="Gate 2 aborted by operator.",
        )

    _append_unassigned_ledger_units(
        target_path=target_path,
        files=deferred_files,
        status="deferred",
        reason=f"Deferred: exceeded budget cap (${effective_budget:.2f} / {token_limit} tokens); higher-risk security paths prioritized first.",
        ledger_units=ledger_units,
        ledger_hashes=ledger_hashes,
        prior_by_id=prior_by_id,
    )
    _append_unassigned_ledger_units(
        target_path=target_path,
        files=out_of_scope_files,
        status="out_of_scope",
        reason=f"Out of scope for diff-scoped audit (unchanged relative to {base_ref or 'base ref'}).",
        ledger_units=ledger_units,
        ledger_hashes=ledger_hashes,
        prior_by_id=prior_by_id,
    )

    ledger_units.sort(key=lambda u: u["coverage_id"])
    schema_findings.sort(key=lambda r: r["fingerprint"])

    findings_json_path = cf_out_dir / "findings.json"
    ledger_json_path = cf_out_dir / "coverage-ledger.json"
    findings_json_path.write_text(scrub_secrets(json.dumps(schema_findings, indent=2)), encoding="utf-8")
    ledger_json_path.write_text(scrub_secrets(json.dumps(ledger_units, indent=2)), encoding="utf-8")

    event_bus.emit_log(run_id, 2, "Phase 4 (Schema Validation): Running Cloudflare validate-findings.cjs and validate-coverage-ledger.cjs...", "info")
    f_ok, f_msg = _run_cloudflare_node_validator(skill_dir, "validate-findings.cjs", findings_json_path)
    l_ok, l_msg = _run_cloudflare_node_validator(skill_dir, "validate-coverage-ledger.cjs", ledger_json_path)

    if skill_dir and find_node():
        event_bus.emit_log(run_id, 2, f"validate-findings.cjs -> {f_msg}", "success" if f_ok else "warn")
        event_bus.emit_log(run_id, 2, f"validate-coverage-ledger.cjs -> {l_msg}", "success" if l_ok else "warn")
    else:
        event_bus.emit_log(run_id, 2, "Cloudflare Node validators unavailable; skipped external schema validation.", "warn")

    event_bus.emit_log(run_id, 2, "Phase 6 (Reporting): Generating and parsing REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md...", "info")
    report_paths = _write_cloudflare_reports(
        cf_out_dir,
        target_path,
        audit_profile,
        effective_scope,
        engine_badge,
        len(prior_by_id),
        findings_list,
        ledger_units,
        usage,
    )
    report_paths["findings.json"] = str(findings_json_path)
    report_paths["coverage-ledger.json"] = str(ledger_json_path)

    md_parsed = parse_cloudflare_markdown_reports(cf_out_dir)
    event_bus.emit_log(
        run_id,
        2,
        f"Unified parser reconciled {len(md_parsed)} Markdown report section(s) with findings.json.",
        "info",
    )

    confirmed_blocking = [
        f for f in findings_list if f.verdict == "confirmed" and f.severity in ("critical", "high")
    ]
    confirmed_nonblocking = [
        f for f in findings_list if f.verdict == "confirmed" and f.severity not in ("critical", "high")
    ]
    needs_validation = [f for f in findings_list if f.verdict == "needs_validation"]
    hardening_notes = [f for f in findings_list if f.verdict == "hardening_note"]
    duration_ms = int((time.perf_counter() - start) * 1000)

    if confirmed_blocking:
        status = "failed"
        summary = (
            f"[{engine_badge}] BLOCKED: {len(confirmed_blocking)} confirmed high/critical vulnerability(s), "
            f"{len(confirmed_nonblocking)} medium/low, {len(needs_validation)} needs-validation."
        )
        event_bus.emit_log(run_id, 2, summary, "error")
    elif confirmed_nonblocking or needs_validation:
        status = "warn"
        summary = (
            f"[{engine_badge}] Passed with review items: 0 critical/high, {len(confirmed_nonblocking)} confirmed medium/low, "
            f"{len(needs_validation)} needs-validation, {len(hardening_notes)} hardening note(s)."
        )
        event_bus.emit_log(run_id, 2, summary, "warn")
    else:
        status = "passed"
        summary = f"[{engine_badge}] Clean: 0 confirmed vulnerabilities across {len(ledger_units)} coverage ledger unit(s)."
        event_bus.emit_log(run_id, 2, summary, "success")

    base_resolved = target_path.resolve()
    return Gate2Result(
        status=status,
        mode=mode,
        engine_badge=engine_badge,
        duration_ms=duration_ms,
        summary=summary,
        findings=findings_list,
        ledger_units=ledger_units,
        ledger_hashes=ledger_hashes,
        report_paths=report_paths,
        metadata={
            "profile": audit_profile,
            "scope": effective_scope,
            "base_ref": base_ref,
            "scope_note": scope_note,
            "direct_imports_included": [f.resolve().relative_to(base_resolved).as_posix() for f in direct_imports],
            "files_audited": [f.resolve().relative_to(base_resolved).as_posix() for f in included_files],
            "files_deferred_budget": [f.resolve().relative_to(base_resolved).as_posix() for f in deferred_files],
            "files_out_of_scope": [f.resolve().relative_to(base_resolved).as_posix() for f in out_of_scope_files],
            "max_budget_usd": effective_budget,
            "token_limit": token_limit,
            "preflight_estimated_tokens": est_input_tokens,
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "estimated_cost_usd": usage.estimated_cost_usd,
            "engine_badge": engine_badge,
            "llm_used": mode == "live_llm",
            "llm_provider": llm_config.provider if (llm_config and mode == "live_llm") else "none",
            "llm_model": llm_config.resolved_model if (llm_config and mode == "live_llm") else "",
            "llm_error": llm_error,
            "ledger_units": len(ledger_units),
            "prior_units_reused": sum(1 for u in ledger_units if u["prior_status"] != "new"),
            "validators": {
                "findings_valid": f_ok,
                "findings_message": f_msg,
                "ledger_valid": l_ok,
                "ledger_message": l_msg,
            },
            "confirmed_blocking": len(confirmed_blocking),
            "confirmed_total": len(confirmed_blocking) + len(confirmed_nonblocking),
            "needs_validation": len(needs_validation),
            "hardening_notes": len(hardening_notes),
            "report_paths": report_paths,
        },
    )
