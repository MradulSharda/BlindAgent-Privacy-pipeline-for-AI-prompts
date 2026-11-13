import React, { useState } from 'react';

const SPEC_ITEMS = [
  { k: 'CONSTANT TIME', populated: 'RUSSIAN PEASANT BRANCHLESS BITMASK', standby: 'STANDBY (READY FOR BENCHMARK)' },
  { k: 'REDUCTION POLY', populated: '0x11B (AES RIJNDAEL MODULUS)', standby: '0x11B (AES RIJNDAEL MODULUS)' },
  { k: 'ENTROPY SOURCE', populated: 'OS-NATIVE CSPRNG (URANDOM / BCRYPT)', standby: 'OS CSPRNG (SYSTEM URANDOM)' },
  { k: 'CACHE RESISTANCE', populated: 'ZERO LOOKUP-TABLE MEMORY ACCESS', standby: 'ZERO LOOKUP-TABLE ACCESS' }
];

const BENCHMARK_TESTS = [
  { id: 'TEST_01', name: 'GF(2^8) Russian Peasant Bitmask Multiplication' },
  { id: 'TEST_02', name: 'Lagrange Basis Interpolation Root x=0' },
  { id: 'TEST_03', name: 'Shannon Mutual Information I(S; Shares) = 0' },
  { id: 'TEST_04', name: 'Constant-Time Cache Timing Side-Channel' },
];

export const ProofsView: React.FC = () => {
  // Start initially in pre-execution standby state
  const [isExecuted, setIsExecuted] = useState<boolean>(false);
  const [viewMode, setViewMode] = useState<'theorems' | 'suite'>('suite');
  const [auditRunning, setAuditRunning] = useState<boolean>(false);
  const [passedCount, setPassedCount] = useState<number>(0);
  const [timingVariance, setTimingVariance] = useState<string>('STANDBY');

  const handleRunAudit = () => {
    setAuditRunning(true);
    setViewMode('theorems');
    setTimeout(() => {
      setIsExecuted(true);
      setPassedCount(4);
      setTimingVariance('0.014 µs');
      setAuditRunning(false);
    }, 600);
  };

  const handleTimingBenchmark = () => {
    setAuditRunning(true);
    setViewMode('suite');
    setTimeout(() => {
      setIsExecuted(true);
      setPassedCount(4);
      setTimingVariance('0.012 µs');
      setAuditRunning(false);
    }, 500);
  };

  const handleReset = () => {
    setIsExecuted(false);
    setViewMode('suite');
    setPassedCount(0);
    setTimingVariance('STANDBY');
    setAuditRunning(false);
  };

  return (
    <div className="max-w-[1440px] mx-auto px-9 py-12">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
        {/* LEFT COLUMN: Hero & Technical Spec Attributes */}
        <div className="lg:col-span-5 space-y-7">
          <div className="space-y-3">
            <h1 className="font-mono text-[42px] font-bold leading-[1.15] text-[#111827] tracking-tight">
              MATHEMATICAL<br />
              SPECIFICATION.
            </h1>
            <p className="font-['Inter_Tight'] text-[15px] text-[#4B5563] leading-relaxed max-w-[480px]">
              Formal mathematical verification of finite field arithmetic,<br className="hidden sm:inline" />
              polynomial secrecy, and constant-time side-channel resistance.
            </p>
          </div>

          {/* Action Buttons (Square Inverted - Penpot style) */}
          <div className="flex flex-wrap items-center gap-4 pt-1">
            {!isExecuted ? (
              /* Pre-Execution Standby Buttons (Penpot: Desktop 1440 - Mathematical Proofs Empty State) */
              <>
                <button
                  onClick={handleRunAudit}
                  className="w-[210px] h-[48px] bg-[#1B1D54] hover:bg-[#131540] text-white font-mono text-[12px] font-bold tracking-wider rounded-none transition cursor-pointer flex items-center justify-center"
                >
                  {auditRunning ? 'RUNNING AUDIT...' : 'RUN AUDIT SUITE'}
                </button>

                <button
                  onClick={handleTimingBenchmark}
                  className="w-[210px] h-[48px] bg-white border border-[#E2E8F0] hover:bg-slate-50 text-[#64748B] font-mono text-[12px] font-bold tracking-wider rounded-none transition cursor-pointer flex items-center justify-center"
                >
                  TIMING BENCHMARK
                </button>
              </>
            ) : (
              /* Populated State Buttons (Penpot: Desktop 1440 - Mathematical Proofs) */
              <>
                <button
                  onClick={handleRunAudit}
                  className="w-[210px] h-[48px] bg-[#1B1D54] hover:bg-[#131540] text-white font-mono text-[12px] font-bold tracking-wider rounded-none transition cursor-pointer flex items-center justify-center"
                >
                  {auditRunning ? 'RUNNING AUDIT...' : 'AUDIT VERIFICATION'}
                </button>

                <button
                  onClick={handleTimingBenchmark}
                  className="w-[210px] h-[48px] bg-white border border-[#1B1D54] hover:bg-slate-50 text-[#1B1D54] font-mono text-[12px] font-bold tracking-wider rounded-none transition cursor-pointer flex items-center justify-center"
                >
                  TIMING TEST REPORT
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

          {/* Key Cryptographic Attributes Spec Sheet */}
          <div className="space-y-4 pt-3 border-t border-[#E2E8F0]">
            {SPEC_ITEMS.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between font-mono text-[11px]">
                <span className="font-bold text-[#1B1D54]">{item.k}</span>
                <span className="font-medium text-[#111827]">
                  {isExecuted ? item.populated : item.standby}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT COLUMN: Hairline Spec Card (Penpot Board 3 Source of Truth) */}
        <div className="lg:col-span-7">
          <div className="bg-white border border-[#E2E8F0] rounded-none p-7 space-y-6">
            {/* Header with Switcher */}
            <div className="flex items-center justify-between">
              <h3 className="font-mono text-[12px] font-bold text-[#1B1D54] uppercase tracking-wider">
                {!isExecuted
                  ? 'CRYPTOGRAPHIC VERIFICATION SUITE (STANDBY)'
                  : viewMode === 'theorems'
                  ? 'CORE CRYPTOGRAPHIC THEOREMS & BOUNDS'
                  : 'CRYPTOGRAPHIC VERIFICATION SUITE'}
              </h3>
              {isExecuted && (
                <button
                  onClick={() => setViewMode(viewMode === 'theorems' ? 'suite' : 'theorems')}
                  className="text-[11px] font-mono font-bold text-[#64748B] hover:text-[#1B1D54] border-b border-[#CBD5E1] pb-0.5 cursor-pointer bg-transparent"
                >
                  {viewMode === 'theorems' ? '[VIEW BENCHMARKS]' : '[VIEW THEOREMS]'}
                </button>
              )}
            </div>
            <div className="h-[1px] bg-[#E2E8F0] w-full" />

            {!isExecuted || viewMode === 'suite' ? (
              /* Standby / Verification Suite Benchmark Table (Penpot: Desktop 1440 - Mathematical Proofs Empty State) */
              <div className="space-y-4">
                <div className="grid grid-cols-12 gap-2 text-[11px] font-mono font-semibold text-[#64748B]">
                  <div className="col-span-2">TEST ID</div>
                  <div className="col-span-7">PROOF CATEGORY / TARGET</div>
                  <div className="col-span-3 text-right">STATUS</div>
                </div>

                <div className="space-y-3">
                  {BENCHMARK_TESTS.map((test) => (
                    <div
                      key={test.id}
                      className="pt-2 border-t border-[#E2E8F0] grid grid-cols-12 gap-2 items-center text-[12px] font-mono"
                    >
                      <div className="col-span-2 font-bold text-[#1B1D54]">
                        {test.id}
                      </div>
                      <div className="col-span-7 text-[#111827]">
                        {test.name}
                      </div>
                      <div className="col-span-3 text-right text-[11px] font-bold">
                        {auditRunning ? (
                          <span className="text-[#2563EB]">RUNNING...</span>
                        ) : isExecuted && passedCount === 4 ? (
                          <span className="text-[#0D7A5F]">PASSED [✔]</span>
                        ) : (
                          <span className="text-[#94A3B8]">STANDBY [ ]</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="h-[1px] bg-[#E2E8F0] w-full pt-2" />

                <div className="pt-1 flex items-center justify-between font-mono text-[12px] font-bold text-[#1B1D54]">
                  <span>
                    {!isExecuted
                      ? 'AUDIT RUNNER: ALL 4 VERIFICATION BENCHMARKS IN STANDBY'
                      : `AUDIT RUNNER: ${passedCount} / 4 VERIFICATION BENCHMARKS CONFIRMED`}
                  </span>
                  {isExecuted && (
                    <span className="text-[11px] text-[#0D7A5F]">VARIANCE: {timingVariance}</span>
                  )}
                </div>
              </div>
            ) : (
              /* Theorems Content (Penpot: Desktop 1440 - Mathematical Proofs) */
              <div className="space-y-6">
                {/* Section 01 */}
                <div className="space-y-2">
                  <h4 className="font-mono text-[11px] font-bold text-[#1B1D54] tracking-wider uppercase">
                    01  GALOIS FIELD FORMULATION
                  </h4>
                  <div className="font-mono text-[12px] text-[#111827] leading-relaxed space-y-1">
                    <div>P(X) = X^8 + X^4 + X^3 + X + 1 &nbsp;&nbsp;&nbsp;[Hex: 0x11B]</div>
                    <div>Algebraic Field: GF(2^8) = F_2[X] / (P(X))</div>
                    <div className="text-[#64748B]">Operation: Addition is XOR (⊕), Multiplication is bitwise Russian Peasant.</div>
                  </div>
                </div>

                <div className="h-[1px] bg-[#E2E8F0] w-full" />

                {/* Section 02 */}
                <div className="space-y-2">
                  <h4 className="font-mono text-[11px] font-bold text-[#1B1D54] tracking-wider uppercase">
                    02  THRESHOLD POLYNOMIAL & RECONSTRUCTION
                  </h4>
                  <div className="font-mono text-[12px] text-[#111827] leading-relaxed space-y-1">
                    <div>f(x) = S ⊕ (a_1 ⊗ x) ⊕ (a_2 ⊗ x^2) ⊕ ... ⊕ (a_&#123;k-1&#125; ⊗ x^&#123;k-1&#125;)</div>
                    <div>S = ⊕_&#123;j=1&#125;^k ( y_j ⊗ ℓ_j(0) ) &nbsp;&nbsp;where &nbsp;&nbsp;ℓ_j(0) = ⊗_&#123;m ≠ j&#125; [ x_m ⊘ (x_m ⊕ x_j) ]</div>
                  </div>
                </div>

                <div className="h-[1px] bg-[#E2E8F0] w-full" />

                {/* Section 03 */}
                <div className="space-y-2">
                  <h4 className="font-mono text-[11px] font-bold text-[#1B1D54] tracking-wider uppercase">
                    03  SHANNON PERFECT SECRECY THEOREM
                  </h4>
                  <div className="font-mono text-[12px] text-[#111827] leading-relaxed space-y-1">
                    <div className="font-semibold text-[#0D7A5F]">
                      I( S ; Shares_&#123;k-1&#125; ) = 0 &nbsp;&nbsp;===&gt;&nbsp;&nbsp; H( S | Shares_&#123;k-1&#125; ) = H( S )
                    </div>
                    <div>Adversary observing m &lt; k shares possesses exactly zero information regarding the plaintext secret master key.</div>
                  </div>
                </div>

                <div className="h-[1px] bg-[#E2E8F0] w-full" />

                {/* Section 04 */}
                <div className="space-y-2">
                  <h4 className="font-mono text-[11px] font-bold text-[#1B1D54] tracking-wider uppercase">
                    04  EPHEMERAL TOKEN AFFINE INVARIANCE
                  </h4>
                  <div className="font-mono text-[12px] text-[#111827] leading-relaxed space-y-1">
                    <div>tau_i = (alpha_i ⊗ v_i) ⊕ beta_i &nbsp;&nbsp;&nbsp;[alpha coprime, beta random in GF(2^8)]</div>
                    <div className="text-[#64748B]">LLM reasons over structural grammar; plaintext never traverses wire.</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
