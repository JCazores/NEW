import { useState, useEffect } from 'react';
import { useAuthStore } from '../../store/authStore';

const AUTO_TOKEN = import.meta.env.VITE_VULNSIGHT_AUTO_TOKEN || 'supersecrettoken123';

export default function NetworkVapt() {
  const user = useAuthStore(state => state.user);
  const [src, setSrc] = useState('');

  useEffect(() => {
    if (!user?.email) return;
    const ts = Date.now();
    setSrc(`http://localhost:8000/vulnsight/auto-login?email=${encodeURIComponent(user.email)}&token=${encodeURIComponent(AUTO_TOKEN)}&_t=${ts}`);
  }, [user?.email]);

  if (!src) return (
    <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'100%',color:'#9ca3af'}}>
      Loading…
    </div>
  );

  return (
    <iframe
      key={src}
      src={src}
      style={{width:'100%',height:'100%',border:'none',minHeight:'calc(100vh - 64px)'}}
      title="VulnSight Network Scanner"
      sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation"
    />
  );
}
