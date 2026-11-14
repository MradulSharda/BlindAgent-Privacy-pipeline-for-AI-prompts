import React, { useState } from 'react';
import { executePipeline, type ExecuteResponse } from '../services/api';

const PRESETS = [
  {
    id: 1,
    name: 'SQL + SSN',
    prompt: 'Please generate an SQL audit query for employee\nSSN: 123-45-6789 and master_key: SuperSecretMasterPassword!\nwith balance $50,000.'
  },
  {
    id: 2,
    name: 'MEDICAL KEY',
    prompt: 'Summarize confidential diagnosis for patient SSN: 987-65-4321 holding authorized api_secret: AIzaSyD988223311AABBC-998811.'
  },
  {
    id: 3,
    name: 'TAGGED SECRET',
    prompt: 'Authorize system transfer for <secret>TOP_SECRET_VAULT_KEY_007</secret> with transaction limit $250,000.'
  },
  {
    id: 4,
    name: 'ENTROPY / MARKOV / CRF TEST',
    prompt: 'User with auth_token 9f8b2c4e1a7d6e3b and password xK9#mQ2! requested access via bearer AIzaSyD988223311AABBC-998811.'
  }
];

export const PlaygroundView: React.FC = () => {
  // Pre-execution initial state
  const [selectedPreset, setSelectedPreset] = useState<number>(0);
  const [prompt, setPrompt] = useState<string>('');
  const [threshold, setThreshold] = useState<number>(3);
  const [totalShares, setTotalShares] = useState<number>(5);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ExecuteResponse | null>(null);

  const handleSelectPreset = async (p: typeof PRESETS[0]) => {
    setSelectedPreset(p.id);
    setPrompt(p.prompt);
    setError(null);
    setLoading(true);
    try {
      const data = await executePipeline(p.prompt, threshold, totalShares);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Execution error');
    } finally {
      setLoading(false);
    }
  };

  const handleExecute = async () => {
    if (!prompt.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await executePipeline(prompt, threshold, totalShares);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Execution error');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setPrompt('');
    setSelectedPreset(0);
    setResult(null);
    setError(null);
  };

  // The view is in pre-execution state whenever no execution has been performed yet
  const isPreExecution = result === null;

  return (
    <div className="max-w-[1440px] mx-auto px-9 py-12">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
        {/* LEFT COLUMN: Hero, Inputs & Inverted Buttons */}
        <div className="lg:col-span-5 space-y-7">
          {/* Headline (Penpot: JetBrains Mono, 42px, 700, line-height 1.15) */}
          <div className="space-y-3">
            <h1 className="font-mono text-[42px] font-bold leading-[1.15] text-[#111827] tracking-tight">
              ZERO-LEAKAGE<br />
              AI PIPELINE.
            </h1>
            <p className="font-['Inter_Tight'] text-[15px] text-[#4B5563] leading-relaxed max-w-[480px]">
              Local client enclave. Multi-layer mathematical detection (RegEx, Shannon Entropy, CRF, Markov N-Gram) with GF(2^8) SSS blinding before cloud transit.
            </p>
          </div>

          {/* Presets Row */}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            {PRESETS.map((p) => {
              const active = selectedPreset === p.id;
              return (
                <button
                  key={p.id}
                  onClick={() => handleSelectPreset(p)}
                  className={`px-3 py-1.5 text-[11px] font-mono font-bold tracking-wider rounded-none transition cursor-pointer ${
                    active
                      ? 'bg-[#1B1D54] text-white'
                      : 'bg-white border border-[#1B1D54] text-[#1B1D54] hover:bg-slate-50'
                  }`}
                >
                  {p.name}
                </button>
              );
            })}
          </div>

          {/* Prompt Textarea Well */}
          <div className="space-y-2">
            <label className="block text-[11px] font-mono font-bold uppercase tracking-wider text-[#1B1D54]">
              USER CONFIDENTIAL PROMPT
            </label>
            <div className="relative">
              <textarea
                value={prompt}
                onChange={(e) => {
                  setPrompt(e.target.value);
                  if (selectedPreset !== 0) setSelectedPreset(0);
                  if (result !== null) setResult(null);
                }}
                rows={4}
                placeholder="Enter sensitive query (e.g. SQL with SSN, API master key, medical credentials)..."
                className="w-full bg-white border border-[#1B1D54] rounded-none p-3 text-[12px] font-mono leading-relaxed text-[#111827] focus:outline-none focus:ring-1 focus:ring-[#1B1D54]"
              />
            </div>
          </div>

          {/* Parameters Row */}
          <div className="space-y-2 text-[12px] font-mono font-bold text-[#1B1D54]">
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-1.5">
                <span>THRESHOLD (K):</span>
                <input
                  type="number"
                  min={2}
                  max={10}
                  value={threshold}
                  onChange={(e) => setThreshold(parseInt(e.target.value) || 3)}
                  className="w-8 text-center border-b border-[#1B1D54] bg-transparent focus:outline-none"
                />
              </div>
              <div className="flex items-center space-x-1.5">
                <span>TOTAL (N):</span>
                <input
                  type="number"
                  min={2}
                  max={10}
                  value={totalShares}
                  onChange={(e) => setTotalShares(parseInt(e.target.value) || 5)}
                  className="w-8 text-center border-b border-[#1B1D54] bg-transparent focus:outline-none"
                />
              </div>
              <span className="text-[#0D7A5F]">C CONSTANT-TIME</span>
            </div>
            <div className="text-[11px] text-[#2563EB] font-mono">
              SCANNER: 4 ENSEMBLE DETECTORS (REGEX + ENTROPY + CRF + MARKOV)
            </div>
          </div>

          {/* Action Buttons (Square Inverted - Penpot style) */}
          <div className="flex items-center space-x-4 pt-1">
            <button
              onClick={handleExecute}
              disabled={loading || !prompt.trim()}
              className="w-[116px] h-[48px] bg-[#1B1D54] hover:bg-[#131540] disabled:opacity-50 text-white font-mono text-[16px] font-bold tracking-wider rounded-none transition flex items-center justify-center cursor-pointer"
            >
              {loading ? (
                <span className="inline-flex items-center text-[12px]">
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  ...
                </span>
              ) : (
                'EXECUTE'
              )}
            </button>

            <button
              onClick={handleReset}
              className="w-[122px] h-[48px] bg-white border border-[#1B1D54] hover:bg-slate-50 text-[#1B1D54] font-mono text-[16px] font-bold tracking-wider rounded-none transition cursor-pointer flex items-center justify-center"
            >
              RESET
            </button>
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 text-red-700 text-xs font-mono rounded-none">
              {error}
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: Hairline Data Table Card (Penpot Source of Truth) */}
        <div className="lg:col-span-7">
          {isPreExecution ? (
            /* Standby Pre-Screen State (Penpot Board: Desktop 1440 - AI Agent Playground Empty State) */
            <div className="bg-white border border-[#E2E8F0] rounded-none w-full min-h-[460px] flex flex-col items-center justify-center p-8 text-center space-y-6">
              <div className="w-[180px] h-[180px] rounded-full border border-[#E2E8F0] flex items-center justify-center bg-[#FAFAFA]">
                <div className="w-[120px] h-[120px] rounded-full border border-[#CBD5E1] flex items-center justify-center bg-white shadow-inner">
                  <div className="w-3.5 h-3.5 bg-[#1B1D54] rounded-full animate-pulse" />
                </div>
              </div>
              <div className="space-y-1.5 max-w-[420px]">
                <div className="font-mono text-[12px] font-bold text-[#1B1D54] tracking-widest uppercase">
                  {prompt.trim() ? 'STANDBY (READY TO EXECUTE)' : 'AWAITING CONFIDENTIAL PROMPT'}
                </div>
                <p className="font-['Inter_Tight'] text-[13px] text-[#64748B] leading-relaxed">
                  {prompt.trim()
                    ? 'Prompt input detected. Click \'EXECUTE\' to evaluate 4-layer detection (RegEx, Entropy, CRF, Markov) and GF(2^8) blinding.'
                    : 'Select a preset above or enter a prompt with sensitive credentials to inspect real-time multi-detector blinding.'}
                </p>
              </div>
            </div>
          ) : (
            /* Populated State (Penpot Board: Desktop 1440 - AI Agent Playground) */
            <div className="bg-white border border-[#E2E8F0] rounded-none p-7 space-y-5">
              {/* Table Header */}
              <div>
                <h3 className="font-mono text-[12px] font-bold text-[#1B1D54] uppercase tracking-wider">
                  SHIELDED ENTITIES & CIPHERTEXT VAULT (LIVE INSPECTION)
                </h3>
              </div>
              <div className="h-[1px] bg-[#E2E8F0] w-full" />

              {/* Table Headers */}
              <div className="grid grid-cols-12 gap-2 text-[11px] font-mono font-semibold text-[#64748B]">
                <div className="col-span-2 min-w-0 truncate">TOKEN ID</div>
                <div className="col-span-3 min-w-0 truncate">ROLE / DETECTOR</div>
                <div className="col-span-3 min-w-0 truncate">ORIGINAL PLAINTEXT</div>
                <div className="col-span-3 min-w-0 truncate">BLINDED WIRE TOKEN</div>
                <div className="col-span-1 min-w-0 text-right">ENCLAVE</div>
              </div>

              {/* Table Rows */}
              <div className="space-y-3">
                {result && result.vault && result.vault.length > 0 ? (
                  result.vault.map((v, idx) => {
                    const cleanTokenId = v.token.match(/BLIND_TOKEN_\d+/)?.[0] || `BLIND_TOKEN_${idx + 1}`;
                    return (
                      <div key={idx} className="pt-2 border-t border-[#E2E8F0] grid grid-cols-12 gap-2 items-center text-[12px] font-mono">
                        <div className="col-span-2 min-w-0 font-bold text-[#1B1D54] truncate" title={cleanTokenId}>
                          {cleanTokenId}
                        </div>
                        <div className="col-span-3 min-w-0 text-[#111827]">
                          <div className="font-semibold truncate" title={v.entity_type}>{v.entity_type}</div>
                          {v.detector && (
                            <div className="text-[10px] text-[#64748B] tracking-tight truncate" title={v.detector}>
                              via {v.detector}
                            </div>
                          )}
                        </div>
                        <div className="col-span-3 min-w-0 font-semibold text-[#0D7A5F] truncate" title={v.original_value}>
                          {v.original_value}
                        </div>
                        <div className="col-span-3 min-w-0 font-semibold text-[#DC2626] truncate text-[11px]" title={v.token}>
                          {v.token}
                        </div>
                        <div className="col-span-1 min-w-0 text-right text-[11px] font-bold text-[#0D7A5F]">
                          SHIELDED
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <div className="pt-2 border-t border-[#E2E8F0] text-[12px] font-mono text-[#64748B] py-3 text-center">
                    No explicit credentials or sensitive tokens detected in prompt.
                  </div>
                )}
              </div>

              {/* Mid Divider */}
              <div className="h-[1px] bg-[#E2E8F0] w-full pt-1" />

              {/* Sub-table: Wire vs Enclave Comparison */}
              <div className="space-y-4 pt-1">
                <div>
                  <div className="text-[11px] font-mono font-bold text-[#DC2626] uppercase">
                    HOST WIRE PAYLOAD (CLOUD LOG)
                  </div>
                  <div className="mt-1 p-2.5 bg-slate-50 border border-[#E2E8F0] rounded-none font-mono text-[11px] text-[#111827] whitespace-pre-wrap break-all">
                    {result ? result.wire_payload : ''}
                  </div>
                </div>

                <div className="h-[1px] bg-[#E2E8F0] w-full" />

                <div>
                  <div className="text-[11px] font-mono font-bold text-[#0D7A5F] uppercase">
                    CLIENT ENCLAVE OUTPUT (RESTORED)
                  </div>
                  <div className="mt-1 p-2.5 bg-slate-50 border border-[#E2E8F0] rounded-none font-mono text-[11px] text-[#1B1D54] whitespace-pre-wrap break-words">
                    {result ? result.final_output : ''}
                  </div>
                </div>
              </div>

              {/* Divider */}
              <div className="h-[1px] bg-[#E2E8F0] w-full" />

              {/* Telemetry Bar */}
              <div className="flex flex-wrap items-center justify-between text-[11px] font-mono font-bold text-[#0D7A5F] pt-1">
                <span>SHIELDED: {result ? result.metrics.entities_protected : 0} ENTITIES</span>
                <span>ENTROPY: {result ? result.metrics.blinded_entropy_bits : 0} BITS</span>
                <span>LATENCY: {result ? result.execution_time_ms : 0} MS</span>
                <span>DETECTORS: 4 ACTIVE (REGEX + ENTROPY + CRF + MARKOV)</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
