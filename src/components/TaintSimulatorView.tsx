import { useState } from 'react';
import { Play, RotateCcw, ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  SIMULATED_SYMLINKS,
  type SessionState,
  type TaintDecision,
} from '../engine/taintEngine';
import { ATTACK_SCENARIOS, type AttackScenario } from '../data/gatewayData';

interface SimulationTraceItem {
  id: string;
  sessionId: string;
  method: string;
  toolName: string;
  argumentsJson: string;
  decision: TaintDecision;
}

interface TaintSimulatorViewProps {
  sessions: Record<string, SessionState>;
  activeSessionId: string;
  onSelectSession: (id: string) => void;
  onEvaluateCall: (params: {
    sessionId: string;
    method: 'tools/call' | 'resources/read';
    toolName: string;
    argumentsObj: unknown;
  }) => TaintDecision;
  onTriggerResponseDlp: (params: {
    sessionId: string;
    toolName: string;
    ruleId: string;
    reason: string;
  }) => void;
  onResetSession: (sessionId: string) => void;
}

export function TaintSimulatorView({
  sessions,
  activeSessionId,
  onSelectSession,
  onEvaluateCall,
  onTriggerResponseDlp,
  onResetSession,
}: TaintSimulatorViewProps) {
  const [method, setMethod] = useState<'tools/call' | 'resources/read'>('tools/call');
  const [toolName, setToolName] = useState('read_file');
  const [argumentsJson, setArgumentsJson] = useState('{"path": ".env"}');
  const [parseError, setParseError] = useState<string | null>(null);
  const [trace, setTrace] = useState<SimulationTraceItem[]>([]);

  const currentSession: SessionState = sessions[activeSessionId] ?? {
    sessionId: activeSessionId,
    level: 'clean',
    records: [],
    totalBlocks: 0,
    taintedAt: null,
  };

  const sessionIds = Array.from(
    new Set([activeSessionId, 'sess-sandbox-01', ...Object.keys(sessions)])
  );

  const handleDispatch = () => {
    setParseError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(argumentsJson);
    } catch (err) {
      setParseError(
        err instanceof Error ? err.message : 'Invalid JSON arguments'
      );
      return;
    }

    const effectiveTool = method === 'resources/read' ? 'resources/read' : toolName;
    const decision = onEvaluateCall({
      sessionId: activeSessionId,
      method,
      toolName: effectiveTool,
      argumentsObj: parsed,
    });

    setTrace((prev) => [
      {
        id: `${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
        sessionId: activeSessionId,
        method,
        toolName: effectiveTool,
        argumentsJson,
        decision,
      },
      ...prev,
    ]);
  };

  const handleRunScenario = (scenario: AttackScenario) => {
    onResetSession(scenario.sessionId);
    onSelectSession(scenario.sessionId);

    const newTraces: SimulationTraceItem[] = [];
    for (const step of scenario.steps) {
      if (step.method === 'response/dlp') {
        const parsed = JSON.parse(step.argumentsJson) as {
          rule_id: string;
          reason: string;
        };
        onTriggerResponseDlp({
          sessionId: scenario.sessionId,
          toolName: step.toolName,
          ruleId: parsed.rule_id,
          reason: parsed.reason,
        });
        newTraces.unshift({
          id: `${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
          sessionId: scenario.sessionId,
          method: 'response/dlp',
          toolName: step.toolName,
          argumentsJson: step.argumentsJson,
          decision: {
            action: 'allow_and_taint',
            allowed: true,
            sessionTainted: true,
            newlyTainted: true,
            toolCategory: 'safe_read',
            reason: `Phase 5 DLP tainted session from response: ${parsed.reason}`,
            ruleId: parsed.rule_id,
            provenance: [],
            latencyMs: 0.24,
          },
        });
      } else {
        const parsed = JSON.parse(step.argumentsJson);
        const decision = onEvaluateCall({
          sessionId: scenario.sessionId,
          method: step.method,
          toolName: step.toolName,
          argumentsObj: parsed,
        });
        newTraces.unshift({
          id: `${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
          sessionId: scenario.sessionId,
          method: step.method,
          toolName: step.toolName,
          argumentsJson: step.argumentsJson,
          decision,
        });
      }
    }
    setTrace((prev) => [...newTraces, ...prev]);
  };

  return (
    <div className="space-y-8">
      {/* Top 2-column Interactive Request Builder & Session State */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">
                Evaluate MCP Request
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Runs live against the Phase 4 taint policy and appends HMAC receipts to Control Center
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label
                htmlFor="sim-session"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Session ID
              </label>
              <select
                id="sim-session"
                value={activeSessionId}
                onChange={(e) => onSelectSession(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-md text-slate-900 focus:outline-none focus:border-slate-900"
              >
                {sessionIds.map((id) => (
                  <option key={id} value={id}>
                    {id}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="sim-method"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                JSON-RPC Method
              </label>
              <select
                id="sim-method"
                value={method}
                onChange={(e) => {
                  const next = e.target.value as 'tools/call' | 'resources/read';
                  setMethod(next);
                  if (next === 'resources/read') {
                    setToolName('resources/read');
                    setArgumentsJson('{"uri": "file:///home/dev/.ssh/id_rsa"}');
                  }
                }}
                className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-md text-slate-900 focus:outline-none focus:border-slate-900"
              >
                <option value="tools/call">tools/call</option>
                <option value="resources/read">resources/read</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="sim-tool"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Tool Name
              </label>
              <input
                id="sim-tool"
                type="text"
                value={method === 'resources/read' ? 'resources/read' : toolName}
                disabled={method === 'resources/read'}
                onChange={(e) => setToolName(e.target.value)}
                placeholder="e.g. read_file, http_post"
                className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-md text-slate-900 disabled:opacity-60 focus:outline-none focus:border-slate-900"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="sim-args"
              className="block text-xs font-medium text-slate-700 mb-1"
            >
              Arguments (JSON)
            </label>
            <textarea
              id="sim-args"
              rows={3}
              value={argumentsJson}
              onChange={(e) => setArgumentsJson(e.target.value)}
              className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-md text-slate-900 focus:outline-none focus:border-slate-900"
            />
            {parseError && (
              <p className="mt-1 text-xs text-red-700 font-mono">{parseError}</p>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <div className="text-xs text-slate-500 font-mono">
              Symlinks in workspace:{' '}
              {Object.entries(SIMULATED_SYMLINKS)
                .map(([k, v]) => `${k} -> ${v.split('/').pop()}`)
                .join(' · ')}
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  onTriggerResponseDlp({
                    sessionId: activeSessionId,
                    toolName: 'read_file',
                    ruleId: 'dlp.aws_secret_key',
                    reason:
                      'High-entropy AWS secret access key detected in upstream response',
                  });
                }}
                className="px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-md hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Trigger DLP Taint
              </button>
              <button
                type="button"
                onClick={handleDispatch}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                Evaluate Call
              </button>
            </div>
          </div>
        </div>

        {/* Active Session Taint State */}
        <div className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-slate-900">
                Session State
              </h2>
              <div className="text-xs font-mono text-slate-500 mt-0.5">
                {currentSession.sessionId} · Monotonic enforcement
              </div>
            </div>
            <button
              type="button"
              onClick={() => onResetSession(currentSession.sessionId)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-md hover:bg-slate-50 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Operator Reset
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3 pt-1">
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-md">
              <div className="text-xs text-slate-500">Taint Level</div>
              <div
                className={`mt-1 flex items-center gap-1.5 text-sm font-mono font-semibold ${
                  currentSession.level === 'tainted'
                    ? 'text-red-700'
                    : 'text-emerald-700'
                }`}
              >
                {currentSession.level === 'tainted' ? (
                  <ShieldAlert className="w-4 h-4 shrink-0" />
                ) : (
                  <ShieldCheck className="w-4 h-4 shrink-0" />
                )}
                <span>{currentSession.level.toUpperCase()}</span>
              </div>
            </div>
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-md">
              <div className="text-xs text-slate-500">Blocked Sinks</div>
              <div className="mt-1 text-sm font-mono font-semibold tabular-nums text-slate-900">
                {currentSession.totalBlocks}
              </div>
            </div>
          </div>

          <div className="border-t border-slate-200 pt-3">
            <div className="text-xs font-medium text-slate-700 mb-2">
              Taint Provenance ({currentSession.records.length})
            </div>
            {currentSession.records.length === 0 ? (
              <p className="text-xs text-slate-500">
                No sensitive sources accessed in this session. Outbound network and write sinks are permitted.
              </p>
            ) : (
              <ul className="space-y-2 max-h-44 overflow-y-auto">
                {currentSession.records.map((rec, i) => (
                  <li
                    key={`${rec.requestId}-${i}`}
                    className="text-xs border-b border-slate-100 pb-2 last:border-b-0 last:pb-0"
                  >
                    <div className="font-mono text-red-700 font-medium">
                      {rec.ruleId}
                    </div>
                    <div className="text-slate-700 mt-0.5">{rec.reason}</div>
                    <div className="text-slate-500 font-mono mt-0.5 truncate">
                      {rec.toolName} · {rec.sourceDetail}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>

      {/* 6 Automated Attack Scenarios */}
      <section className="space-y-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900">
            6-Attack Verification Scenarios
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Run multi-step exfiltration and bypass chains mirroring tests/test_taint.py
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {ATTACK_SCENARIOS.map((scenario) => (
            <div
              key={scenario.id}
              className="bg-white border border-slate-200 rounded-lg p-4 flex flex-col justify-between gap-4"
            >
              <div>
                <h3 className="text-sm font-semibold text-slate-900">
                  {scenario.title}
                </h3>
                <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                  {scenario.description}
                </p>
              </div>
              <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-100">
                <span className="text-xs font-mono text-slate-500">
                  {scenario.steps.length} step{scenario.steps.length > 1 ? 's' : ''}
                </span>
                <button
                  type="button"
                  onClick={() => handleRunScenario(scenario)}
                  className="px-3 py-1.5 text-xs font-medium text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Run Scenario
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Evaluation Trace */}
      {trace.length > 0 && (
        <section className="bg-white border border-slate-200 rounded-lg">
          <div className="p-4 border-b border-slate-200 flex items-center justify-between">
            <h2 className="text-base font-semibold text-slate-900">
              Recent Evaluation Trace
            </h2>
            <button
              type="button"
              onClick={() => setTrace([])}
              className="text-xs text-slate-500 hover:text-slate-900 cursor-pointer"
            >
              Clear trace
            </button>
          </div>
          <div className="divide-y divide-slate-100">
            {trace.slice(0, 10).map((item) => (
              <div
                key={item.id}
                className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
              >
                <div className="space-y-0.5 min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5 font-mono">
                    <span
                      className={
                        item.decision.action === 'block'
                          ? 'text-red-700 font-semibold'
                          : item.decision.action === 'allow_and_taint'
                          ? 'text-amber-700 font-semibold'
                          : 'text-emerald-700 font-semibold'
                      }
                    >
                      {item.decision.action.toUpperCase()}
                    </span>
                    <span className="text-slate-300">·</span>
                    <span className="text-slate-900 font-medium">
                      {item.toolName}
                    </span>
                    <span className="text-slate-300">·</span>
                    <span className="text-slate-500">
                      {item.decision.toolCategory}
                    </span>
                    <span className="text-slate-300">·</span>
                    <span className="text-slate-500">{item.sessionId}</span>
                  </div>
                  <div className="text-slate-700">{item.decision.reason}</div>
                  <div className="font-mono text-slate-500 truncate">
                    args: {item.argumentsJson}
                  </div>
                </div>
                <div className="font-mono tabular-nums text-slate-500 whitespace-nowrap shrink-0">
                  {item.decision.latencyMs.toFixed(2)} ms
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
