import { useMemo, useState } from 'react';
import { Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { AuditEvent } from '../engine/taintEngine';
import { verifyAuditChain } from '../engine/taintEngine';
import { LOCKED_TOOL_REGISTRY } from '../data/gatewayData';

interface ControlCenterViewProps {
  events: AuditEvent[];
  onToggleTamper: () => void;
  isTamperedSimulated: boolean;
}

type EventFilter = 'all' | 'blocked' | 'taint' | 'redacted' | 'allowed';

export function ControlCenterView({
  events,
  onToggleTamper,
  isTamperedSimulated,
}: ControlCenterViewProps) {
  const [filter, setFilter] = useState<EventFilter>('all');
  const [query, setQuery] = useState('');
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);

  const chainStatus = useMemo(() => verifyAuditChain(events), [events]);

  const kpis = useMemo(() => {
    const total = events.length;
    const blocked = events.filter((e) => e.decision === 'BLOCK').length;
    const redacted = events.filter((e) => e.decision === 'REDACT').length;
    const taintBlocks = events.filter(
      (e) => e.decision === 'BLOCK' && e.category === 'taint'
    ).length;
    return { total, blocked, redacted, taintBlocks };
  }, [events]);

  const filteredEvents = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...events]
      .reverse()
      .filter((ev) => {
        if (filter === 'blocked' && ev.decision !== 'BLOCK') return false;
        if (filter === 'taint' && ev.category !== 'taint') return false;
        if (filter === 'redacted' && ev.decision !== 'REDACT') return false;
        if (
          filter === 'allowed' &&
          ev.decision !== 'ALLOW' &&
          ev.decision !== 'ALLOW_AND_TAINT'
        ) {
          return false;
        }
        if (!q) return true;
        return (
          ev.toolName.toLowerCase().includes(q) ||
          ev.sessionId.toLowerCase().includes(q) ||
          ev.ruleId.toLowerCase().includes(q) ||
          ev.reason.toLowerCase().includes(q)
        );
      });
  }, [events, filter, query]);

  const selectedEvent = useMemo(
    () => events.find((e) => e.seq === selectedSeq) ?? null,
    [events, selectedSeq]
  );

  const decisionTextClass = (decision: AuditEvent['decision']) => {
    if (decision === 'BLOCK') return 'text-red-700 font-semibold';
    if (decision === 'ALLOW_AND_TAINT' || decision === 'REDACT') {
      return 'text-amber-700 font-semibold';
    }
    return 'text-emerald-700 font-semibold';
  };

  return (
    <div className="space-y-8">
      {/* KPI Strip */}
      <section aria-label="Gateway KPIs">
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="bg-white border border-slate-200 rounded-lg p-4">
            <div className="text-xs font-medium text-slate-500">Total Events</div>
            <div className="mt-2 text-2xl font-semibold text-slate-900 font-mono tabular-nums">
              {kpis.total}
            </div>
            <div className="mt-1 text-xs text-slate-500">logs/audit.jsonl</div>
          </div>

          <div className="bg-white border border-slate-200 rounded-lg p-4">
            <div className="text-xs font-medium text-slate-500">Blocked</div>
            <div className="mt-2 text-2xl font-semibold text-red-700 font-mono tabular-nums">
              {kpis.blocked}
            </div>
            <div className="mt-1 text-xs text-slate-500">Fail-closed denials</div>
          </div>

          <div className="bg-white border border-slate-200 rounded-lg p-4">
            <div className="text-xs font-medium text-slate-500">Redacted</div>
            <div className="mt-2 text-2xl font-semibold text-amber-700 font-mono tabular-nums">
              {kpis.redacted}
            </div>
            <div className="mt-1 text-xs text-slate-500">DLP secret masks</div>
          </div>

          <div className="bg-white border border-slate-200 rounded-lg p-4">
            <div className="text-xs font-medium text-slate-500">Taint Blocks</div>
            <div className="mt-2 text-2xl font-semibold text-red-700 font-mono tabular-nums">
              {kpis.taintBlocks}
            </div>
            <div className="mt-1 text-xs text-slate-500">Phase 4 sink denials</div>
          </div>

          <div className="col-span-2 lg:col-span-1 bg-white border border-slate-200 rounded-lg p-4 flex flex-col justify-between">
            <div>
              <div className="text-xs font-medium text-slate-500">Audit Chain</div>
              <div
                className={`mt-2 flex items-center gap-1.5 text-lg font-semibold font-mono ${
                  chainStatus.verified ? 'text-emerald-700' : 'text-red-700'
                }`}
              >
                {chainStatus.verified ? (
                  <ShieldCheck className="w-4 h-4 shrink-0" />
                ) : (
                  <ShieldAlert className="w-4 h-4 shrink-0" />
                )}
                <span>{chainStatus.verified ? 'VERIFIED' : 'TAMPERED'}</span>
              </div>
            </div>
            <div className="mt-2 flex items-center justify-between gap-2">
              <span className="text-xs text-slate-500 font-mono tabular-nums truncate">
                {chainStatus.verified
                  ? 'HMAC-SHA256 valid'
                  : `Broken at seq #${chainStatus.brokenSeq}`}
              </span>
              <button
                type="button"
                onClick={onToggleTamper}
                className="text-xs font-medium text-slate-700 hover:text-slate-950 underline underline-offset-2 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {isTamperedSimulated ? 'Restore' : 'Test tamper'}
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Audit Event Feed */}
      <section className="bg-white border border-slate-200 rounded-lg">
        <div className="p-4 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              Audit Event Feed
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Read-only stream over logs/audit.jsonl · Click any row to inspect HMAC receipt
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter tool, session, or rule..."
                aria-label="Filter audit events"
                className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-md text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-slate-900 w-56"
              />
            </div>

            <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md">
              {(
                [
                  ['all', 'All'],
                  ['blocked', 'Blocked'],
                  ['taint', 'Taint'],
                  ['redacted', 'Redacted'],
                  ['allowed', 'Allowed'],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setFilter(key)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    filter === key
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-medium text-slate-500 bg-slate-50/70">
                <th className="py-2.5 px-4 font-mono">Seq</th>
                <th className="py-2.5 px-4">Decision</th>
                <th className="py-2.5 px-4">Session &amp; Method</th>
                <th className="py-2.5 px-4">Tool</th>
                <th className="py-2.5 px-4">Rule &amp; Reason</th>
                <th className="py-2.5 px-4 text-right">Overhead</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 px-4 text-center text-slate-500">
                    No audit records match the current filter.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => {
                  const isSelected = selectedSeq === ev.seq;
                  const isBrokenRow =
                    !chainStatus.verified && chainStatus.brokenSeq === ev.seq;
                  return (
                    <tr
                      key={ev.seq}
                      onClick={() =>
                        setSelectedSeq(isSelected ? null : ev.seq)
                      }
                      className={`cursor-pointer transition-colors ${
                        isBrokenRow
                          ? 'bg-red-50/80 hover:bg-red-50'
                          : isSelected
                          ? 'bg-slate-100/80'
                          : 'hover:bg-slate-50'
                      }`}
                    >
                      <td className="py-2.5 px-4 font-mono tabular-nums text-slate-600 whitespace-nowrap">
                        #{ev.seq}
                      </td>
                      <td
                        className={`py-2.5 px-4 font-mono whitespace-nowrap ${decisionTextClass(
                          ev.decision
                        )}`}
                      >
                        {ev.decision}
                      </td>
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <span className="font-mono text-slate-900">
                          {ev.sessionId}
                        </span>
                        <span className="mx-1.5 text-slate-300">·</span>
                        <span className="font-mono text-slate-500">
                          {ev.method}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-900 whitespace-nowrap">
                        {ev.toolName}
                      </td>
                      <td className="py-2.5 px-4 max-w-md">
                        <div className="font-mono text-slate-700 truncate">
                          {ev.ruleId}
                        </div>
                        <div className="text-slate-500 truncate mt-0.5">
                          {ev.reason}
                        </div>
                      </td>
                      <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-600 whitespace-nowrap">
                        {ev.latencyMs.toFixed(2)} ms
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {selectedEvent && (
          <div className="p-4 border-t border-slate-200 bg-slate-50/70">
            <div className="flex items-center justify-between gap-4 mb-2">
              <div className="text-xs font-semibold text-slate-900">
                Receipt #{selectedEvent.seq} · {selectedEvent.timestamp}
              </div>
              <button
                type="button"
                onClick={() => setSelectedSeq(null)}
                className="text-xs text-slate-500 hover:text-slate-900 cursor-pointer"
              >
                Close
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
              <div className="bg-white border border-slate-200 rounded p-2.5">
                <div className="text-slate-500">prev_hmac</div>
                <div className="text-slate-900 break-all mt-0.5">
                  {selectedEvent.prevHmac}
                </div>
              </div>
              <div className="bg-white border border-slate-200 rounded p-2.5">
                <div className="text-slate-500">hmac</div>
                <div className="text-slate-900 break-all mt-0.5">
                  {selectedEvent.hmac}
                </div>
              </div>
            </div>
            <p className="mt-2.5 text-xs text-slate-700">
              {selectedEvent.reason}
            </p>
          </div>
        )}
      </section>

      {/* Locked SQLite Tool Registry */}
      <section className="bg-white border border-slate-200 rounded-lg">
        <div className="p-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              Locked SQLite Tool Registry
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Read-only URI mode (PRAGMA query_only = ON) · SHA-256 ToolFingerprint &amp; executable pinning
            </p>
          </div>
          <div className="text-xs font-mono text-slate-500 tabular-nums">
            {LOCKED_TOOL_REGISTRY.filter((r) => r.status === 'LOCKED').length}{' '}
            pinned ·{' '}
            {LOCKED_TOOL_REGISTRY.filter((r) => r.status === 'DRIFT_BLOCKED').length}{' '}
            blocked
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-medium text-slate-500 bg-slate-50/70">
                <th className="py-2.5 px-4">Server ID</th>
                <th className="py-2.5 px-4">Tool Name</th>
                <th className="py-2.5 px-4">Category</th>
                <th className="py-2.5 px-4">Schema SHA-256</th>
                <th className="py-2.5 px-4">Executable SHA-256</th>
                <th className="py-2.5 px-4 text-right">CDR Stripped</th>
                <th className="py-2.5 px-4">State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {LOCKED_TOOL_REGISTRY.map((tool) => (
                <tr
                  key={`${tool.serverId}-${tool.toolName}`}
                  className="hover:bg-slate-50"
                >
                  <td className="py-2.5 px-4 font-mono text-slate-700 whitespace-nowrap">
                    {tool.serverId}
                  </td>
                  <td className="py-2.5 px-4 font-mono font-medium text-slate-900 whitespace-nowrap">
                    {tool.toolName}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-600 whitespace-nowrap">
                    {tool.category}
                  </td>
                  <td className="py-2.5 px-4 font-mono tabular-nums text-slate-600 whitespace-nowrap">
                    {tool.schemaSha256.slice(0, 16)}…
                  </td>
                  <td className="py-2.5 px-4 font-mono tabular-nums text-slate-600 whitespace-nowrap">
                    {tool.executableSha256.slice(0, 16)}…
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-700 whitespace-nowrap">
                    {tool.cdrStrippedCount}
                  </td>
                  <td
                    className={`py-2.5 px-4 font-mono font-semibold whitespace-nowrap ${
                      tool.status === 'LOCKED'
                        ? 'text-emerald-700'
                        : 'text-red-700'
                    }`}
                  >
                    {tool.status}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
