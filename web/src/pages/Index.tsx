import { useVault } from '@/contexts/VaultContext';
import EnrollPage from '@/pages/EnrollPage';
import UnlockPage from '@/pages/UnlockPage';
import DashboardPage from '@/pages/DashboardPage';
import { useEffect, useState } from 'react';

const Index = () => {
  const { isUnlocked, isEnrolled } = useVault();
  const [mode, setMode] = useState<'login' | 'register'>('login');

  // Reset mode to 'login' once the user reaches the dashboard so that
  // locking the session later shows the Login page, not the Register page.
  useEffect(() => {
    if (isUnlocked && !isEnrolled) {
      setMode('login');
    }
  }, [isUnlocked, isEnrolled]);

  if (!isUnlocked || isEnrolled) {
    if (mode === 'register' || isEnrolled) {
      return <EnrollPage onSwitchToLogin={() => setMode('login')} />;
    }
    return <UnlockPage onSwitchToRegister={() => setMode('register')} />;
  }
  return <DashboardPage />;
};

export default Index;
