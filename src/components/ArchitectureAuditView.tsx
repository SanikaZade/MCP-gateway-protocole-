import { ARCHITECTURE_EDGE_CASES } from '../data/gatewayData';

export function ArchitectureAuditView() {
  return (
    <div className="space-y-6">
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <h2 className="text-base font-semibold text-slate-900">
          Fail-Closed Architecture Threat Review
        </h2>
        <p className="text-sm text-slate-600 mt-1.5 max-w-3xl leading-relaxed">
          Six high-impact edge cases identified across the local-first mcp-gw pipeline (Phases 1–6 and the read-only Control Center). Items EC-01 through EC-03 are enforced directly in the Phase 4{' '}
          <code className="font-mono text-xs bg-slate-100 px-1.5 py-0.5 rounded text-slate-900">
            mcp_gw/taint.py
          </code>{' '}
          implementation; EC-04 through EC-06 specify exact hardening constraints for adjacent modules.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {ARCHITECTURE_EDGE_CASES.map((item) => (
          <article
            key={item.id}
            className="bg-white border border-slate-200 rounded-lg p-5 flex flex-col justify-between gap-4"
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-3 text-xs font-mono">
                <span className="text-slate-500">
                  {item.id} · {item.phase} · {item.module}
                </span>
                <span
                  className={
                    item.severity === 'Critical'
                      ? 'text-red-700 font-semibold'
                      : 'text-amber-700 font-semibold'
                  }
                >
                  {item.severity}
                </span>
              </div>

              <h3 className="text-sm font-semibold text-slate-900">
                {item.title}
              </h3>

              <div className="space-y-2 text-xs leading-relaxed">
                <div>
                  <span className="font-semibold text-slate-900">
                    Attack vector:{' '}
                  </span>
                  <span className="text-slate-600">{item.vulnerability}</span>
                </div>
                <div>
                  <span className="font-semibold text-slate-900">
                    Fail-closed mitigation:{' '}
                  </span>
                  <span className="text-slate-700">{item.hardening}</span>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs">
              <span
                className={
                  item.status === 'Implemented in taint.py'
                    ? 'font-mono font-medium text-emerald-700'
                    : 'font-mono font-medium text-slate-600'
                }
              >
                {item.status}
              </span>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}
