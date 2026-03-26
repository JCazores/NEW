import { useState, useEffect } from 'react';
import { useAuthStore } from '../../store/authStore';

const VS_URL      = 'http://localhost:8001';
const VS_TOKEN    = import.meta.env.VITE_VULNSIGHT_AUTO_TOKEN  || 'supersecrettoken123';
const ADMIN_EMAIL = import.meta.env.VITE_VULNSIGHT_ADMIN_EMAIL || 'admin@gmail.com';

export default function AdminWebVapt() {
  const user = useAuthStore(state => state.user);
  const [src, setSrc] = useState('');

  useEffect(() => {
    if (!user?.email) return;
    const ts = Date.now();
    setSrc(`${VS_URL}/auto-login?email=${encodeURIComponent(ADMIN_EMAIL)}&token=${encodeURIComponent(VS_TOKEN)}&_t=${ts}`);
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
      title="VulnSight Admin"
      sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation"
    />
  );
}
