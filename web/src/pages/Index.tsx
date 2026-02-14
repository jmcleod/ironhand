import { useVault } from '@/contexts/VaultContext';
import EnrollPage from '@/pages/EnrollPage';
import UnlockPage from '@/pages/UnlockPage';
import DashboardPage from '@/pages/DashboardPage';
import { useState } from 'react';

const Index = () => {
  const { isUnlocked } = useVault();
  const [mode, setMode] = useState<'login' | 'register'>('login');

  if (!isUnlocked) {
    if (mode === 'register') {
      return <EnrollPage onSwitchToLogin={() => setMode('login')} />;
    }
    return <UnlockPage onSwitchToRegister={() => setMode('register')} />;
  }
  return <DashboardPage />;
};

export default Index;
