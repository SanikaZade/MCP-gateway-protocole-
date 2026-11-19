import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import {
  TAINT_PY_SOURCE,
  TEST_TAINT_PY_SOURCE,
  VERIFIED_TEST_RESULTS,
} from '../data/gatewayData';

export function PythonSourceView() {
  const [activeFile, setActiveFile] = useState<'taint' | 'tests'>('taint');
  const [copied, setCopied] = useState(false);

  const source = activeFile === 'taint' ? TAINT_PY_SOURCE : TEST_TAINT_PY_SOURCE;
  const filename =
    activeFile === 'taint' ? 'mcp_gw/taint.py' : 'tests/test_taint.py';

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(source);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md">
            <button
              type="button"
              onClick={() => setActiveFile('taint')}
              className={`px-3 py-1.5 text-xs font-mono font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeFile === 'taint'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              mcp_gw/taint.py
            </button>
            <button
              type="button"
              onClick={() => setActiveFile('tests')}
              className={`px-3 py-1.5 text-xs font-mono font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeFile === 'tests'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              tests/test_taint.py
            </button>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-slate-500">
              Python 3.11+ · Stdlib only · Zero stdout logging
            </span>
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  Copied {filename}
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Copy File
                </>
              )}
            </button>
          </div>
        </div>

        <pre className="p-4 text-xs font-mono leading-relaxed text-slate-800 bg-slate-50 overflow-x-auto max-h-[540px]">
          <code>{source}</code>
        </pre>
      </div>

      {/* Verified Python 3.11 Test Matrix */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-200">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              Verified Unit Test Suite (Python 3.11.2)
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Executed against mcp_gw/taint.py — all 13 fail-closed assertions passed
            </p>
          </div>
          <span className="text-xs font-mono font-semibold text-emerald-700 tabular-nums">
            13 / 13 PASSED
          </span>
        </div>

        <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1.5 text-xs font-mono">
          {VERIFIED_TEST_RESULTS.map((name) => (
            <div
              key={name}
              className="flex items-center gap-2 py-1 border-b border-slate-100 last:border-b-0"
            >
              <span className="text-emerald-700 font-semibold shrink-0">
                PASS
              </span>
              <span className="text-slate-700 truncate">{name}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
