import React, { useState } from 'react';
import { splitSecret, combineShares } from '../services/api';

const SAMPLE_SECRET = 'MY-SECRET-FINANCIAL-API-TOKEN-8833';

export const SSSLabView: React.FC = () => {
  // Start initially in pre-execution state
  const [secret, setSecret] = useState<string>('');
  const [k, setK] = useState<number>(3);
  const [n, setN] = useState<number>(5);
  const [shares, setShares] = useState<string[]>([]);
  const [selectedShares, setSelectedShares] = useState<Set<number>>(new Set());
  const [recoveredSecret, setRecoveredSecret] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const isPopulated = shares.length > 0;

  const handleGenerate = async () => {
    if (!secret.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await splitSecret(secret, k, n);
      setShares(data.shares);
      const initial = new Set<number>();
      for (let i = 0; i < Math.min(k, data.shares.length); i++) initial.add(i);
      setSelectedShares(initial);
      setRecoveredSecret('');
      
      // Auto-reconstruct immediately with the first k shares
      const chosen = data.shares.slice(0, k);
      const comb = await combineShares(chosen, k);
      if (comb.recovered) {
        setRecoveredSecret(comb.recovered);
      }
    } catch (err: any) {
      setError(err.message || 'Generation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSample = () => {
    setSecret(SAMPLE_SECRET);
    setK(3);
    setN(5);
    const sampleShares = [
      '017b94a28f10b5c92e34d09a4f21557c8b0193ea774412',
      '02c318e47a9d0124f5a892b10493aa82df5518b03e2189',
      '034fa910bb32de8194c5021a48ef2019bb84cc912044fe',
      '0499d2140a8751e2bc1049a02ef891ca8234bb721098de',
      '05fe1190ca3824bb8849aa018d94e2197701ca529944cc',
    ];
    setShares(sampleShares);
    setSelectedShares(new Set([0, 1, 2]));
    setRecoveredSecret(SAMPLE_SECRET);
    setError(null);
  };

  const handleReset = () => {
    setSecret('');
    setShares([]);
    setSelectedShares(new Set());
    setRecoveredSecret('');
    setError(null);
  };

  const handleToggleShare = (idx: number) => {
    const updated = new Set(selectedShares);
    if (updated.has(idx)) {
      updated.delete(idx);
    } else {
      updated.add(idx);
    }
    setSelectedShares(updated);
  };

  const handleReconstruct = async () => {
    if (selectedShares.size < k) {
      setError(`Need at least ${k} shares to reconstruct. You selected ${selectedShares.size}.`);
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const chosen = Array.from(selectedShares).map((idx) => shares[idx]);
      const data = await combineShares(chosen, k);
      if (data.recovered) {
        setRecoveredSecret(data.recovered);
      } else {
        setError(data.detail || 'Reconstruction failed');
      }
    } catch (err: any) {
      setError(err.message || 'Reconstruction failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-[1440px] mx-auto px-9 py-12">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
        {/* LEFT COLUMN: Controls & Headline */}
        <div className="lg:col-span-5 space-y-7">
          <div className="space-y-3">
            <h1 className="font-mono text-[42px] font-bold leading-[1.15] text-[#111827] tracking-tight">
              GALOIS FIELD<br />
              SECRET SHARING.
            </h1>
            <p className="font-['Inter_Tight'] text-[15px] text-[#4B5563] leading-relaxed max-w-[480px]">
              Constant-time polynomial secret sharing over GF(2^8).<br className="hidden sm:inline" />
              Threshold-based reconstruction with information-theoretic zero leakage.
            </p>
          </div>

          {/* Secret to Split Input */}
          <div className="space-y-2">
            <label className="block text-[11px] font-mono font-bold uppercase tracking-wider text-[#1B1D54]">
              SECRET TO SPLIT
            </label>
            <input
              type="text"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder="Enter secret token or key to split into polynomial shares..."
              className="w-full bg-white border border-[#1B1D54] rounded-none h-[44px] px-3 text-[13px] font-mono text-[#111827] focus:outline-none focus:ring-1 focus:ring-[#1B1D54]"
            />
          </div>

          {/* Parameters Row */}
          <div className="flex items-center space-x-8 text-[12px] font-mono font-bold text-[#1B1D54]">
            <div className="flex items-center space-x-2">
              <span>THRESHOLD (K):</span>
              <input
                type="number"
                min={2}
                max={10}
                value={k}
                onChange={(e) => setK(parseInt(e.target.value) || 3)}
                className="w-8 text-center border-b border-[#1B1D54] bg-transparent focus:outline-none"
              />
            </div>
            <div className="flex items-center space-x-2">
              <span>TOTAL SHARES (N):</span>
              <input
                type="number"
                min={2}
                max={10}
                value={n}
                onChange={(e) => setN(parseInt(e.target.value) || 5)}
                className="w-8 text-center border-b border-[#1B1D54] bg-transparent focus:outline-none"
              />
            </div>
          </div>

          {/* Action Buttons (Square Inverted - Penpot style) */}
          <div className="flex flex-wrap items-center gap-4 pt-1">
            <button
              onClick={handleGenerate}
              disabled={loading || !secret.trim()}
              className="w-[190px] h-[48px] bg-[#1B1D54] hover:bg-[#131540] disabled:opacity-50 text-white font-mono text-[12px] font-bold tracking-wider rounded-none transition flex items-center justify-center cursor-pointer"
            >
              {loading ? 'GENERATING...' : 'GENERATE SHARES'}
            </button>

            {!isPopulated ? (
              <button
                onClick={handleLoadSample}
                className="w-[210px] h-[48px] bg-white border border-[#E2E8F0] hover:bg-slate-50 text-[#64748B] font-mono text-[12px] font-bold tracking-wider rounded-none transition cursor-pointer flex items-center justify-center"
              >
                LOAD SAMPLE KEY
              </button>
            ) : (
              <>
                <button
                  onClick={handleReconstruct}
                  disabled={loading || selectedShares.size === 0}
                  className="w-[210px] h-[48px] bg-white border border-[#1B1D54] hover:bg-slate-50 text-[#1B1D54] font-mono text-[12px] font-bold tracking-wider rounded-none transition cursor-pointer flex items-center justify-center"
                >
                  RECONSTRUCT (X=0)
                </button>

                <button
                  onClick={handleReset}
                  className="px-5 h-[48px] bg-white border border-[#CBD5E1] hover:bg-slate-50 text-[#64748B] font-mono text-[12px] font-bold tracking-wider rounded-none transition cursor-pointer flex items-center justify-center"
                >
                  RESET
                </button>
              </>
            )}
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 text-red-700 text-xs font-mono rounded-none">
              {error}
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: Hairline Shares Data Table Card (Penpot Board 2 Source of Truth) */}
        <div className="lg:col-span-7">
          <div className="bg-white border border-[#E2E8F0] rounded-none p-7 space-y-5">
            {/* Header */}
            <div>
              <h3 className="font-mono text-[12px] font-bold text-[#1B1D54] uppercase tracking-wider">
                {!isPopulated ? 'EVALUATED SHARES (STANDBY)' : 'EVALUATED SHARES (LAGRANGE RECONSTRUCTION)'}
              </h3>
            </div>
            <div className="h-[1px] bg-[#E2E8F0] w-full" />

            {/* Table Headers */}
            <div className="grid grid-cols-12 gap-2 text-[11px] font-mono font-semibold text-[#64748B]">
              <div className="col-span-2">ID</div>
              <div className="col-span-7">COORDINATE (X, F(X))</div>
              <div className="col-span-3 text-right">STATUS</div>
            </div>

            {/* Table Rows */}
            <div className="space-y-3">
              {!isPopulated ? (
                /* Standby Pre-Execution Rows (Penpot: Desktop 1440 - Galois Field SSS Lab Empty State) */
                [1, 2, 3, 4, 5].map((rowId) => (
                  <div
                    key={rowId}
                    className="pt-2 border-t border-[#E2E8F0] grid grid-cols-12 gap-2 items-center text-[12px] font-mono text-[#94A3B8]"
                  >
                    <div className="col-span-2 font-medium">
                      {String(rowId).padStart(2, '0')}
                    </div>
                    <div className="col-span-7 font-normal">
                      Awaiting secret generation...
                    </div>
                    <div className="col-span-3 text-right text-[11px] font-medium">
                      EMPTY [ ]
                    </div>
                  </div>
                ))
              ) : (
                /* Active Populated Rows (Penpot: Desktop 1440 - Galois Field SSS Lab) */
                shares.map((share, idx) => {
                  const isSelected = selectedShares.has(idx);
                  return (
                    <div
                      key={idx}
                      onClick={() => handleToggleShare(idx)}
                      className="pt-2 border-t border-[#E2E8F0] grid grid-cols-12 gap-2 items-center text-[12px] font-mono cursor-pointer hover:bg-slate-50/60 transition select-none"
                    >
                      <div className="col-span-2 flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          className="accent-[#1B1D54] w-3.5 h-3.5 rounded-none"
                        />
                        <span className="font-bold text-[#1B1D54]">
                          {String(idx + 1).padStart(2, '0')}
                        </span>
                      </div>

                      <div className="col-span-7 font-normal text-[#111827] truncate" title={share}>
                        x={idx + 1}: {share}
                      </div>

                      <div className="col-span-3 text-right text-[11px] font-bold">
                        {isSelected ? (
                          <span className="text-[#1B1D54]">SELECTED [x]</span>
                        ) : (
                          <span className="text-[#64748B]">OMITTED  [ ]</span>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Divider */}
            <div className="h-[1px] bg-[#E2E8F0] w-full pt-1" />

            {/* Outcome Display */}
            <div className="space-y-1.5 pt-1">
              <div className="font-mono text-[12px] font-bold text-[#1B1D54]">
                RECOVERED: "{!isPopulated ? '---' : recoveredSecret || '---'}"
              </div>
              <div className="font-mono text-[11px] font-medium text-[#64748B]">
                {!isPopulated
                  ? 'THRESHOLD CHECK: AWAITING AT LEAST K SHARES TO INTERPOLATE'
                  : `THRESHOLD CHECK: ${selectedShares.size} / ${k} SHARES ${
                      selectedShares.size >= k
                        ? 'SATISFIED. ZERO LEAKAGE.'
                        : `SELECTED (NEED AT LEAST ${k}).`
                    }`}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
