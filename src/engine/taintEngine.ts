export type TaintLevel = 'clean' | 'tainted';
export type TaintSeverity = 'high' | 'critical';
export type ToolCategory =
  | 'safe_read'
  | 'sensitive_source'
  | 'network_sink'
  | 'write_sink'
  | 'exec_sink'
  | 'unknown';
export type TaintDecisionAction = 'allow' | 'allow_and_taint' | 'block';

export interface TaintRecord {
  sessionId: string;
  timestamp: string;
  reason: string;
  ruleId: string;
  severity: TaintSeverity;
  toolName: string;
  sourceDetail: string;
  requestId: string;
  method: string;
}

export interface TaintDecision {
  action: TaintDecisionAction;
  allowed: boolean;
  sessionTainted: boolean;
  newlyTainted: boolean;
  toolCategory: ToolCategory;
  reason: string;
  ruleId: string | null;
  provenance: TaintRecord[];
  latencyMs: number;
}

export interface SessionState {
  sessionId: string;
  level: TaintLevel;
  records: TaintRecord[];
  totalBlocks: number;
  taintedAt: string | null;
}

export interface AuditEvent {
  seq: number;
  timestamp: string;
  sessionId: string;
  method: string;
  toolName: string;
  decision: 'ALLOW' | 'ALLOW_AND_TAINT' | 'BLOCK' | 'REDACT';
  category: 'taint' | 'policy' | 'dlp' | 'handshake' | 'framing';
  ruleId: string;
  reason: string;
  latencyMs: number;
  prevHmac: string;
  hmac: string;
  tampered?: boolean;
}

const SAFE_READ_TOOLS = new Set([
  'read_file',
  'fs_read_file',
  'fs.read_file',
  'read_multiple_files',
  'list_directory',
  'list_dir',
  'fs.list_dir',
  'search_files',
  'grep_files',
  'get_file_info',
  'stat_file',
  'directory_tree',
  'resources/read',
]);

const EXEC_RE =
  /(?:^|[._\-/])(?:exec|execute|shell|bash|sh|zsh|cmd|powershell|run_command|run_script|spawn|subprocess|eval|terminal|pty|system)(?:$|[._\-/])/i;
const NETWORK_RE =
  /(?:^|[._\-/])(?:http|https|fetch|curl|wget|request|webhook|post|put|upload|send|email|mail|smtp|slack|discord|teams|notify|socket|dns|graphql|rpc|api_call|git_push|push|publish|exfil|remote|sync)(?:$|[._\-/])/i;
const WRITE_RE =
  /(?:^|[._\-/])(?:write|append|create_file|edit|patch|modify|save|delete|remove|unlink|rename|move|copy|cp|mv|chmod|chown|mkdir|put_object|insert|update|upsert|drop|truncate|commit)(?:$|[._\-/])/i;

const SENSITIVE_FILENAME_PATTERNS = [
  /^\.env$/i,
  /^\.env\..+$/i,
  /^.+\.env$/i,
  /^id_(?:rsa|ed25519|ecdsa|dsa)(?:\..+)?$/i,
  /^(?:authorized_keys|known_hosts|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.pgpass|credentials(?:\.json)?|secrets\.(?:ya?ml|json)|master\.key|shadow)$/i,
  /^.+\.(?:pem|key|p12|pfx|kdbx)$/i,
];

const SENSITIVE_DIR_SEGMENTS = new Set(['.ssh', '.aws', '.gnupg', '.kube', '.azure', '.docker']);

const INLINE_SENSITIVE_RULES: Array<{ id: string; re: RegExp; reason: string }> = [
  {
    id: 'taint.inline.env_file',
    re: /(?:^|[\s'"=@:/\\])\.env(?:\.[A-Za-z0-9_.\-]+)?(?:$|[\s'"&;|>])/,
    reason: 'Inline reference to .env credentials file',
  },
  {
    id: 'taint.inline.ssh_dir',
    re: /(?:~|\/home\/[^/\s]+|\/root|\/Users\/[^/\s]+)?\/\.ssh(?:\/|$|[\s'"])/,
    reason: 'Inline reference to SSH key directory (~/.ssh)',
  },
  {
    id: 'taint.inline.aws_creds',
    re: /(?:~|\/home\/[^/\s]+|\/root|\/Users\/[^/\s]+)?\/\.aws\/credentials\b/,
    reason: 'Inline reference to AWS credentials store',
  },
  {
    id: 'taint.inline.proc_environ',
    re: /\/proc\/(?:self|\d+)\/environ\b/,
    reason: 'Inline reference to process environment memory (/proc/self/environ)',
  },
  {
    id: 'taint.inline.etc_shadow',
    re: /\/etc\/shadow\b/,
    reason: 'Inline reference to system shadow file',
  },
  {
    id: 'taint.inline.private_key_name',
    re: /\b(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)\b/,
    reason: 'Inline reference to SSH private key filename',
  },
];

// Simulated workspace symlinks for the interactive simulator
export const SIMULATED_SYMLINKS: Record<string, string> = {
  'notes.txt': '/workspace/project/.env.production',
  'readme_alias.txt': '/workspace/project/.env',
  'harmless.md': '/home/dev/.ssh/id_ed25519',
};

export function classifyTool(toolName: string): ToolCategory {
  const normalized = toolName.trim().toLowerCase();
  if (!normalized) return 'unknown';
  if (EXEC_RE.test(normalized)) return 'exec_sink';
  if (NETWORK_RE.test(normalized)) return 'network_sink';
  if (WRITE_RE.test(normalized)) return 'write_sink';
  if (SAFE_READ_TOOLS.has(normalized)) return 'safe_read';
  return 'unknown';
}

function normalizePosixPath(raw: string): string {
  let cleaned = raw.trim().replace(/^['"]|['"]$/g, '');
  if (cleaned.toLowerCase().startsWith('file://')) {
    const rest = cleaned.slice(7);
    const slashIdx = rest.indexOf('/');
    const host = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
    if (host && host !== 'localhost' && host !== '127.0.0.1') {
      throw new Error(`Non-local file URI host rejected: ${host}`);
    }
    cleaned = decodeURIComponent(slashIdx === -1 ? '/' : rest.slice(slashIdx));
  }
  if (cleaned.startsWith('~/')) {
    cleaned = `/home/dev/${cleaned.slice(2)}`;
  } else if (cleaned === '~') {
    cleaned = '/home/dev';
  } else if (!cleaned.startsWith('/')) {
    cleaned = `/workspace/project/${cleaned}`;
  }

  // Collapse .. and . segments
  const parts = cleaned.split('/');
  const resolved: string[] = [];
  for (const part of parts) {
    if (!part || part === '.') continue;
    if (part === '..') {
      resolved.pop();
    } else {
      resolved.push(part);
    }
  }
  const canonical = `/${resolved.join('/')}`;
  const leaf = resolved[resolved.length - 1] ?? '';

  // Follow simulated workspace symlinks
  if (SIMULATED_SYMLINKS[leaf] && canonical.startsWith('/workspace/project/')) {
    return SIMULATED_SYMLINKS[leaf];
  }
  return canonical;
}

interface SensitiveMatch {
  ruleId: string;
  reason: string;
  severity: TaintSeverity;
  sourceDetail: string;
}

function checkCanonicalPath(canonical: string, wasSymlink: boolean): SensitiveMatch | null {
  const segments = canonical.split('/').filter(Boolean);
  const basename = segments[segments.length - 1] ?? '';

  if (canonical.startsWith('/proc/self') || canonical === '/etc/shadow') {
    return {
      ruleId: wasSymlink ? 'taint.path.symlink_target' : 'taint.path.sensitive_dir',
      reason: `Access to sensitive system boundary: ${canonical}`,
      severity: 'critical',
      sourceDetail: canonical,
    };
  }

  for (const seg of segments) {
    if (SENSITIVE_DIR_SEGMENTS.has(seg.toLowerCase())) {
      return {
        ruleId: wasSymlink ? 'taint.path.symlink_target' : 'taint.path.sensitive_dir',
        reason: wasSymlink
          ? `Symlink resolves into sensitive directory '${seg}'`
          : `Access to sensitive directory boundary '${seg}'`,
        severity: 'critical',
        sourceDetail: canonical,
      };
    }
  }

  for (const rx of SENSITIVE_FILENAME_PATTERNS) {
    if (rx.test(basename)) {
      return {
        ruleId: wasSymlink ? 'taint.path.symlink_target' : 'taint.path.sensitive_file',
        reason: wasSymlink
          ? `Symlink resolves to sensitive file '${basename}'`
          : `Access to sensitive file '${basename}'`,
        severity: 'critical',
        sourceDetail: canonical,
      };
    }
  }

  return null;
}

function extractStringLeaves(payload: unknown, maxNodes = 2048, maxDepth = 16): string[] {
  const leaves: string[] = [];
  const stack: Array<{ val: unknown; depth: number }> = [{ val: payload, depth: 0 }];
  let visited = 0;

  while (stack.length > 0) {
    const item = stack.pop()!;
    visited += 1;
    if (visited > maxNodes) {
      throw new Error(`Tool arguments exceed maximum node budget (${maxNodes})`);
    }
    if (item.depth > maxDepth) {
      throw new Error(`Tool arguments exceed maximum nesting depth (${maxDepth})`);
    }
    if (typeof item.val === 'string') {
      if (item.val.includes('\u0000') || item.val.includes('\\x00')) {
        throw new Error('Path contains illegal NUL byte');
      }
      leaves.push(item.val);
    } else if (Array.isArray(item.val)) {
      for (const child of item.val) {
        stack.push({ val: child, depth: item.depth + 1 });
      }
    } else if (item.val && typeof item.val === 'object') {
      for (const [k, v] of Object.entries(item.val as Record<string, unknown>)) {
        if (k.includes('\u0000')) {
          throw new Error('Argument key contains illegal NUL byte');
        }
        stack.push({ val: v, depth: item.depth + 1 });
      }
    }
  }
  return leaves;
}

function inspectLeaf(rawValue: string): SensitiveMatch | null {
  const stripped = rawValue.trim();
  if (!stripped) return null;

  const isHttp = /^https?:\/\//i.test(stripped);
  const hasWhitespace = /\s/.test(stripped);

  if (!hasWhitespace && !isHttp) {
    const leafCandidate = stripped.split('/').pop() ?? stripped;
    const wasSymlink = Boolean(SIMULATED_SYMLINKS[leafCandidate]);
    const canonical = normalizePosixPath(stripped);
    const match = checkCanonicalPath(canonical, wasSymlink);
    if (match) return match;
  }

  for (const rule of INLINE_SENSITIVE_RULES) {
    if (rule.re.test(stripped)) {
      return {
        ruleId: rule.id,
        reason: rule.reason,
        severity: 'critical',
        sourceDetail: `inline:${rule.id}`,
      };
    }
  }

  if (hasWhitespace || stripped.includes('=') || stripped.includes('@')) {
    const tokens = stripped.split(/[\s=@]+/);
    for (const tok of tokens) {
      const clean = tok.replace(/^['"();|&<>]+|['"();|&<>]+$/g, '');
      if (!clean || /^https?:\/\//i.test(clean) || /^-[A-Za-z]$/.test(clean)) continue;
      const leafCandidate = clean.split('/').pop() ?? clean;
      const wasSymlink = Boolean(SIMULATED_SYMLINKS[leafCandidate]);
      const canonical = normalizePosixPath(clean);
      const match = checkCanonicalPath(canonical, wasSymlink);
      if (match) return match;
    }
  }

  return null;
}

export function evaluateTaintStep(
  sessions: Record<string, SessionState>,
  params: {
    sessionId: string;
    toolName: string;
    method?: string;
    argumentsObj: unknown;
    requestId: string;
  }
): { decision: TaintDecision; nextSessions: Record<string, SessionState> } {
  const start = performance.now();
  const method = params.method ?? 'tools/call';
  const category = classifyTool(params.toolName);
  const prevState: SessionState = sessions[params.sessionId] ?? {
    sessionId: params.sessionId,
    level: 'clean',
    records: [],
    totalBlocks: 0,
    taintedAt: null,
  };
  const nextState: SessionState = {
    ...prevState,
    records: [...prevState.records],
  };

  let sensitiveMatch: SensitiveMatch | null = null;
  try {
    const leaves = extractStringLeaves(params.argumentsObj);
    for (const leaf of leaves) {
      const m = inspectLeaf(leaf);
      if (m) {
        sensitiveMatch = m;
        break;
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Argument inspection failed';
    nextState.totalBlocks += 1;
    const latencyMs = Number(Math.max(0.08, performance.now() - start).toFixed(2));
    return {
      decision: {
        action: 'block',
        allowed: false,
        sessionTainted: nextState.level === 'tainted',
        newlyTainted: false,
        toolCategory: category,
        reason: `Fail-closed argument inspection error: ${message}`,
        ruleId: 'taint.block.fail_closed_inspection',
        provenance: nextState.records,
        latencyMs,
      },
      nextSessions: { ...sessions, [params.sessionId]: nextState },
    };
  }

  const nowIso = new Date().toISOString();

  if (nextState.level === 'tainted') {
    if (
      category === 'network_sink' ||
      category === 'write_sink' ||
      category === 'exec_sink' ||
      category === 'unknown'
    ) {
      nextState.totalBlocks += 1;
      const ruleMap: Record<string, { ruleId: string; reason: string }> = {
        network_sink: {
          ruleId: 'taint.block.network_sink',
          reason: 'Blocked outbound network sink in tainted session',
        },
        write_sink: {
          ruleId: 'taint.block.write_sink',
          reason: 'Blocked write/mutation sink in tainted session',
        },
        exec_sink: {
          ruleId: 'taint.block.exec_sink',
          reason: 'Blocked command execution sink in tainted session',
        },
        unknown: {
          ruleId: 'taint.block.unknown_tool_fail_closed',
          reason: 'Fail-closed: blocked unclassified tool in tainted session',
        },
      };
      const info = ruleMap[category];
      const latencyMs = Number(Math.max(0.09, performance.now() - start).toFixed(2));
      return {
        decision: {
          action: 'block',
          allowed: false,
          sessionTainted: true,
          newlyTainted: false,
          toolCategory: category,
          reason: info.reason,
          ruleId: info.ruleId,
          provenance: nextState.records,
          latencyMs,
        },
        nextSessions: { ...sessions, [params.sessionId]: nextState },
      };
    }

    if (sensitiveMatch) {
      nextState.records.push({
        sessionId: params.sessionId,
        timestamp: nowIso,
        reason: sensitiveMatch.reason,
        ruleId: sensitiveMatch.ruleId,
        severity: sensitiveMatch.severity,
        toolName: params.toolName,
        sourceDetail: sensitiveMatch.sourceDetail,
        requestId: params.requestId,
        method,
      });
    }

    const latencyMs = Number(Math.max(0.07, performance.now() - start).toFixed(2));
    return {
      decision: {
        action: 'allow',
        allowed: true,
        sessionTainted: true,
        newlyTainted: false,
        toolCategory: category,
        reason: 'Allowed safe local read in tainted session',
        ruleId: null,
        provenance: nextState.records,
        latencyMs,
      },
      nextSessions: { ...sessions, [params.sessionId]: nextState },
    };
  }

  if (sensitiveMatch) {
    const rec: TaintRecord = {
      sessionId: params.sessionId,
      timestamp: nowIso,
      reason: sensitiveMatch.reason,
      ruleId: sensitiveMatch.ruleId,
      severity: sensitiveMatch.severity,
      toolName: params.toolName,
      sourceDetail: sensitiveMatch.sourceDetail,
      requestId: params.requestId,
      method,
    };
    nextState.level = 'tainted';
    nextState.taintedAt = nowIso;
    nextState.records.push(rec);

    const isSink =
      category === 'network_sink' || category === 'write_sink' || category === 'exec_sink';
    if (isSink) {
      nextState.totalBlocks += 1;
      const latencyMs = Number(Math.max(0.11, performance.now() - start).toFixed(2));
      return {
        decision: {
          action: 'block',
          allowed: false,
          sessionTainted: true,
          newlyTainted: true,
          toolCategory: category,
          reason: `Blocked single-shot ${category} referencing sensitive source: ${sensitiveMatch.reason}`,
          ruleId: 'taint.block.single_shot_sink',
          provenance: nextState.records,
          latencyMs,
        },
        nextSessions: { ...sessions, [params.sessionId]: nextState },
      };
    }

    const latencyMs = Number(Math.max(0.1, performance.now() - start).toFixed(2));
    return {
      decision: {
        action: 'allow_and_taint',
        allowed: true,
        sessionTainted: true,
        newlyTainted: true,
        toolCategory: category,
        reason: `Session tainted on dispatch: ${sensitiveMatch.reason}`,
        ruleId: sensitiveMatch.ruleId,
        provenance: nextState.records,
        latencyMs,
      },
      nextSessions: { ...sessions, [params.sessionId]: nextState },
    };
  }

  const latencyMs = Number(Math.max(0.06, performance.now() - start).toFixed(2));
  return {
    decision: {
      action: 'allow',
      allowed: true,
      sessionTainted: false,
      newlyTainted: false,
      toolCategory: category,
      reason: 'Clean session; tool call permitted',
      ruleId: null,
      provenance: [],
      latencyMs,
    },
    nextSessions: { ...sessions, [params.sessionId]: nextState },
  };
}

// Deterministic synchronous digest matching audit.jsonl chain verification semantics
export function computeAuditHmac(prevHmac: string, payload: string): string {
  const input = `${prevHmac}|mcp-gw-audit-key-v1|${payload}`;
  let h1 = 0xdeadbeef ^ input.length;
  let h2 = 0x41c6ce57 ^ input.length;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const p1 = (h1 >>> 0).toString(16).padStart(8, '0');
  const p2 = (h2 >>> 0).toString(16).padStart(8, '0');
  const p3 = ((h1 ^ h2) >>> 0).toString(16).padStart(8, '0');
  const p4 = ((h1 + h2) >>> 0).toString(16).padStart(8, '0');
  return `${p1}${p2}${p3}${p4}`;
}

export function verifyAuditChain(events: AuditEvent[]): {
  verified: boolean;
  brokenSeq: number | null;
} {
  let prev = '00000000000000000000000000000000';
  for (const ev of events) {
    const canonical = `${ev.seq}|${ev.timestamp}|${ev.sessionId}|${ev.method}|${ev.toolName}|${ev.decision}|${ev.ruleId}|${ev.reason}`;
    const expected = computeAuditHmac(prev, canonical);
    if (ev.prevHmac !== prev || ev.hmac !== expected) {
      return { verified: false, brokenSeq: ev.seq };
    }
    prev = ev.hmac;
  }
  return { verified: true, brokenSeq: null };
}
