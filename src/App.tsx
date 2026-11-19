import { useCallback, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Code2,
  FlaskConical,
  Menu,
  Shield,
  X,
} from 'lucide-react';
import {
  computeAuditHmac,
  evaluateTaintStep,
  type AuditEvent,
  type SessionState,
  type TaintDecision,
} from './engine/taintEngine';
import { buildInitialAuditEvents } from './data/gatewayData';
import { ControlCenterView } from './components/ControlCenterView';
import { TaintSimulatorView } from './components/TaintSimulatorView';
import { ArchitectureAuditView } from './components/ArchitectureAuditView';
import { PythonSourceView } from './components/PythonSourceView';

type ActiveTab = 'control-center' | 'taint-simulator' | 'architecture' | 'python-source';

const NAV_ITEMS: Array<{
  id: ActiveTab;
  label: string;
  breadcrumb: string;
  icon: typeof Activity;
}> = [
  {
    id: 'control-center',
    label: 'Control Center',
    breadcrumb: 'Security Control Center',
    icon: Activity,
  },
  {
    id: 'taint-simulator',
    label: 'Phase 4 Taint Engine',
    breadcrumb: 'Phase 4 · Session Taint Simulator',
    icon: FlaskConical,
  },
  {
    id: 'architecture',
    label: 'Threat Review',
    breadcrumb: 'Architecture Edge Cases',
    icon: Shield,
  },
  {
    id: 'python-source',
    label: 'Python Source',
    breadcrumb: 'mcp_gw/taint.py & pytest Suite',
    icon: Code2,
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('control-center');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>(() =>
    buildInitialAuditEvents()
  );
  const [tamperedIndex, setTamperedIndex] = useState<number | null>(null);

  const [sessions, setSessions] = useState<Record<string, SessionState>>({
    'sess-sandbox-01': {
      sessionId: 'sess-sandbox-01',
      level: 'clean',
      records: [],
      totalBlocks: 0,
      taintedAt: null,
    },
  });
  const [activeSessionId, setActiveSessionId] = useState('sess-sandbox-01');

  // Keep a ref synced with latest sessions so multi-step scenarios evaluate sequentially
  const sessionsRef = useRef(sessions);
  sessionsRef.current = sessions;

  const appendAuditEvent = useCallback(
    (entry: Omit<AuditEvent, 'seq' | 'prevHmac' | 'hmac'>) => {
      setAuditEvents((prev) => {
        const last = prev[prev.length - 1];
        const prevHmac = last ? last.hmac : '00000000000000000000000000000000';
        const seq = prev.length + 1;
        const canonical = `${seq}|${entry.timestamp}|${entry.sessionId}|${entry.method}|${entry.toolName}|${entry.decision}|${entry.ruleId}|${entry.reason}`;
        const hmac = computeAuditHmac(prevHmac, canonical);
        return [
          ...prev,
          {
            seq,
            ...entry,
            prevHmac,
            hmac,
          },
        ];
      });
    },
    []
  );

  const handleEvaluateCall = useCallback(
    (params: {
      sessionId: string;
      method: 'tools/call' | 'resources/read';
      toolName: string;
      argumentsObj: unknown;
    }): TaintDecision => {
      const reqId = `req-${Date.now().toString(36)}`;
      const { decision, nextSessions } = evaluateTaintStep(sessionsRef.current, {
        sessionId: params.sessionId,
        toolName: params.toolName,
        method: params.method,
        argumentsObj: params.argumentsObj,
        requestId: reqId,
      });
      sessionsRef.current = nextSessions;
      setSessions(nextSessions);

      appendAuditEvent({
        timestamp: new Date().toISOString(),
        sessionId: params.sessionId,
        method: params.method,
        toolName: params.toolName,
        decision:
          decision.action === 'block'
            ? 'BLOCK'
            : decision.action === 'allow_and_taint'
            ? 'ALLOW_AND_TAINT'
            : 'ALLOW',
        category: 'taint',
        ruleId: decision.ruleId ?? 'taint.allow.clean_or_safe',
        reason: decision.reason,
        latencyMs: decision.latencyMs,
      });

      return decision;
    },
    [appendAuditEvent]
  );

  const handleTriggerResponseDlp = useCallback(
    (params: {
      sessionId: string;
      toolName: string;
      ruleId: string;
      reason: string;
    }) => {
      const nowIso = new Date().toISOString();
      const prev = sessionsRef.current[params.sessionId] ?? {
        sessionId: params.sessionId,
        level: 'clean',
        records: [],
        totalBlocks: 0,
        taintedAt: null,
      };
      const updated: SessionState = {
        ...prev,
        level: 'tainted',
        taintedAt: prev.taintedAt ?? nowIso,
        records: [
          ...prev.records,
          {
            sessionId: params.sessionId,
            timestamp: nowIso,
            reason: params.reason,
            ruleId: params.ruleId,
            severity: 'critical',
            toolName: params.toolName,
            sourceDetail: `dlp:${params.ruleId}`,
            requestId: `dlp-${Date.now().toString(36)}`,
            method: 'tools/call',
          },
        ],
      };
      const nextSessions = {
        ...sessionsRef.current,
        [params.sessionId]: updated,
      };
      sessionsRef.current = nextSessions;
      setSessions(nextSessions);

      appendAuditEvent({
        timestamp: nowIso,
        sessionId: params.sessionId,
        method: 'tools/call',
        toolName: params.toolName,
        decision: 'REDACT',
        category: 'dlp',
        ruleId: params.ruleId,
        reason: `${params.reason} — masked [REDACTED] & session tainted`,
        latencyMs: 0.24,
      });
    },
    [appendAuditEvent]
  );

  const handleResetSession = useCallback((sessionId: string) => {
    const clean: SessionState = {
      sessionId,
      level: 'clean',
      records: [],
      totalBlocks: 0,
      taintedAt: null,
    };
    const nextSessions = {
      ...sessionsRef.current,
      [sessionId]: clean,
    };
    sessionsRef.current = nextSessions;
    setSessions(nextSessions);
  }, []);

  const displayedEvents = useMemo(() => {
    if (tamperedIndex === null || tamperedIndex >= auditEvents.length) {
      return auditEvents;
    }
    return auditEvents.map((ev, idx) =>
      idx === tamperedIndex
        ? {
            ...ev,
            reason: `${ev.reason} [edited out-of-band]`,
            tampered: true,
          }
        : ev
    );
  }, [auditEvents, tamperedIndex]);

  const handleToggleTamper = useCallback(() => {
    setTamperedIndex((prev) =>
      prev === null ? Math.max(0, Math.min(2, auditEvents.length - 1)) : null
    );
  }, [auditEvents.length]);

  const activeNav = NAV_ITEMS.find((item) => item.id === activeTab)!;

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-[#0F172A] flex">
      {/* Desktop Sidebar */}
      <aside className="hidden md:flex md:w-[248px] md:shrink-0 md:flex-col bg-white border-r border-slate-200">
        <div className="h-14 px-5 flex items-center border-b border-slate-200">
          <span className="font-mono text-sm font-semibold tracking-tight text-slate-900 whitespace-nowrap">
            mcp-gw
          </span>
        </div>

        <nav className="flex-1 p-3 space-y-1" aria-label="Main navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  isActive
                    ? 'bg-slate-900 text-white'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-200 space-y-1 text-xs text-slate-500">
          <div className="font-mono text-slate-700">127.0.0.1:8787</div>
          <div>Read-only local gateway console · Zero hot-path overhead</div>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          <div
            className="fixed inset-0 bg-slate-900/40"
            onClick={() => setMobileMenuOpen(false)}
          />
          <aside className="relative w-64 max-w-[80vw] bg-white h-full flex flex-col border-r border-slate-200 z-10">
            <div className="h-14 px-4 flex items-center justify-between border-b border-slate-200">
              <span className="font-mono text-sm font-semibold text-slate-900">
                mcp-gw
              </span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close menu"
                className="p-1.5 text-slate-600 hover:text-slate-900 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <nav className="flex-1 p-3 space-y-1">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveTab(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                      isActive
                        ? 'bg-slate-900 text-white'
                        : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 px-4 md:px-8 bg-white border-b border-slate-200 flex items-center justify-between gap-4 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation"
              className="md:hidden p-1.5 text-slate-600 hover:text-slate-900 cursor-pointer"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2 text-xs text-slate-500 truncate">
              <span className="font-mono text-slate-700 hidden sm:inline">
                mcp-gw
              </span>
              <span className="text-slate-300 hidden sm:inline">/</span>
              <h1 className="text-sm font-semibold text-slate-900 truncate">
                {activeNav.breadcrumb}
              </h1>
            </div>
          </div>

          <div className="shrink-0">
            {activeTab !== 'taint-simulator' ? (
              <button
                type="button"
                onClick={() => setActiveTab('taint-simulator')}
                className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Open Taint Simulator
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setActiveTab('python-source')}
                className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Inspect taint.py
              </button>
            )}
          </div>
        </header>

        <main className="flex-1 p-4 md:p-8 max-w-[1280px] w-full mx-auto">
          {activeTab === 'control-center' && (
            <ControlCenterView
              events={displayedEvents}
              onToggleTamper={handleToggleTamper}
              isTamperedSimulated={tamperedIndex !== null}
            />
          )}

          {activeTab === 'taint-simulator' && (
            <TaintSimulatorView
              sessions={sessions}
              activeSessionId={activeSessionId}
              onSelectSession={setActiveSessionId}
              onEvaluateCall={handleEvaluateCall}
              onTriggerResponseDlp={handleTriggerResponseDlp}
              onResetSession={handleResetSession}
            />
          )}

          {activeTab === 'architecture' && <ArchitectureAuditView />}

          {activeTab === 'python-source' && <PythonSourceView />}
        </main>
      </div>
    </div>
  );
}
