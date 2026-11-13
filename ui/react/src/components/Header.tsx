import React from 'react';

interface HeaderProps {
  activeTab: 'playground' | 'sss-lab' | 'proofs';
  onTabChange: (tab: 'playground' | 'sss-lab' | 'proofs') => void;
}

export const Header: React.FC<HeaderProps> = ({ activeTab, onTabChange }) => {
  return (
    <header className="border-b border-[#E2E8F0] bg-white sticky top-0 z-50">
      <div className="max-w-[1440px] mx-auto px-9 h-[72px] flex items-center justify-between">
        {/* Brand Wordmark (Penpot: Inter Tight, 25px, Bold 700, #1B1D54) */}
        <div className="flex items-center">
          <button
            onClick={() => onTabChange('playground')}
            className="text-[25px] font-bold tracking-tight text-[#1B1D54] hover:opacity-90 transition font-['Inter_Tight'] cursor-pointer border-none bg-transparent p-0"
          >
            BLINDAGENT
          </button>
        </div>

        {/* Monospace Navigation Tabs (Penpot: JetBrains Mono, 16px, 700 active / 500 inactive) */}
        <nav className="flex items-center space-x-8 font-mono relative h-[72px]">
          <button
            onClick={() => onTabChange('playground')}
            className={`h-full flex items-center text-[16px] transition cursor-pointer relative border-none bg-transparent px-1 ${
              activeTab === 'playground'
                ? 'font-bold text-[#1B1D54]'
                : 'font-medium text-[#64748B] hover:text-[#1B1D54]'
            }`}
          >
            01 AI AGENT PLAYGROUND
            {activeTab === 'playground' && (
              <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#1B1D54]" />
            )}
          </button>

          <button
            onClick={() => onTabChange('sss-lab')}
            className={`h-full flex items-center text-[16px] transition cursor-pointer relative border-none bg-transparent px-1 ${
              activeTab === 'sss-lab'
                ? 'font-bold text-[#1B1D54]'
                : 'font-medium text-[#64748B] hover:text-[#1B1D54]'
            }`}
          >
            02 GALOIS FIELD SSS LAB
            {activeTab === 'sss-lab' && (
              <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#1B1D54]" />
            )}
          </button>

          <button
            onClick={() => onTabChange('proofs')}
            className={`h-full flex items-center text-[16px] transition cursor-pointer relative border-none bg-transparent px-1 ${
              activeTab === 'proofs'
                ? 'font-bold text-[#1B1D54]'
                : 'font-medium text-[#64748B] hover:text-[#1B1D54]'
            }`}
          >
            03 MATHEMATICAL PROOFS
            {activeTab === 'proofs' && (
              <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#1B1D54]" />
            )}
          </button>
        </nav>
      </div>
    </header>
  );
};
