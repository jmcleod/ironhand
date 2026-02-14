import { useVault } from '@/contexts/VaultContext';
import EnrollPage from '@/pages/EnrollPage';
import UnlockPage from '@/pages/UnlockPage';
import DashboardPage from '@/pages/DashboardPage';
import { useState } from 'react';

const Index = () => {
  const { isUnlocked, isEnrolled } = useVault();
  const [mode, setMode] = useState<'login' | 'register'>('login');

  if (!isUnlocked || isEnrolled) {
    if (mode === 'register' || isEnrolled) {
      return <EnrollPage onSwitchToLogin={() => setMode('login')} />;
    }
    return <UnlockPage onSwitchToRegister={() => setMode('register')} />;
  }
  return <DashboardPage />;
};

export default Index;
