import { useEffect, useState } from 'react';
import { Header } from './components/Header';
import { PlaygroundView } from './components/PlaygroundView';
import { SSSLabView } from './components/SSSLabView';
import { ProofsView } from './components/ProofsView';
import { Footer } from './components/Footer';
import { fetchServerStatus } from './services/api';

export function App() {
  const [activeTab, setActiveTab] = useState<'playground' | 'sss-lab' | 'proofs'>('playground');

  useEffect(() => {
    fetchServerStatus().catch(() => {});
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-white text-[#0F172A]">
      <Header activeTab={activeTab} onTabChange={setActiveTab} />
      <main className="flex-1">
        {activeTab === 'playground' && <PlaygroundView />}
        {activeTab === 'sss-lab' && <SSSLabView />}
        {activeTab === 'proofs' && <ProofsView />}
      </main>
      <Footer activeTab={activeTab} />
    </div>
  );
}

export default App;
