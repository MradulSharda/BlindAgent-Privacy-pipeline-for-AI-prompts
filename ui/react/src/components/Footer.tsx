import React from 'react';

interface FooterProps {
  activeTab: 'playground' | 'sss-lab' | 'proofs';
}

export const Footer: React.FC<FooterProps> = ({ activeTab }) => {
  const getFooterText = () => {
    switch (activeTab) {
      case 'playground':
        return 'BLINDAGENT © 2026. PRIVACY PIPELINE FOR AI PROMPTS. ZERO TELEMETRY LEAKAGE.';
      case 'sss-lab':
        return 'BLINDAGENT © 2026. PRIVACY PIPELINE FOR AI PROMPTS. ZERO-LEAKAGE SSS.';
      case 'proofs':
        return 'BLINDAGENT © 2026. PRIVACY PIPELINE FOR AI PROMPTS. FORMAL MATHEMATICAL AUDIT.';
    }
  };

  return (
    <footer className="border-t border-[#E2E8F0] bg-white py-6 mt-auto">
      <div className="max-w-[1440px] mx-auto px-9 flex items-center justify-between text-[11px] font-mono text-[#64748B]">
        <span>{getFooterText()}</span>
        <span className="hidden sm:inline">C CONSTANT-TIME GF(2^8) 0x11B</span>
      </div>
    </footer>
  );
};
