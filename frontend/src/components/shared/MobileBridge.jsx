import React, { useEffect, useRef, useState } from 'react';
import { useAuthStore } from '../../store/authStore';

const FLASK_API = 'http://127.0.0.1:8002/api';  // Laravel mobile backend
const VAPT_API      = 'http://127.0.0.1:8000/api';
const MOBILE_ORIGIN = 'http://localhost:3000';

function derivedPassword(email) {
  return 'VAPTmobile_' + btoa(email).replace(/=/g, '');
}

export default function MobileBridge() {
  const { user: storeUser, token } = useAuthStore();
  const [ready, setReady]          = useState(false);
  const [error, setError]          = useState(null);
  const sanctumTokenRef            = useRef(null);
  const vaptUserRef                = useRef(null);
  const flaskUserRef               = useRef(null);
  const iframeRef                  = useRef(null);
  const iframeLoadedRef            = useRef(false);
  const syncRan                    = useRef(false);

  useEffect(() => {
    if (!token || syncRan.current) return;
    syncRan.current = true;

    const run = async () => {
      try {
        let vaptUser = storeUser?.email ? storeUser : null;
        if (!vaptUser) {
          const res = await fetch(`${VAPT_API}/user`, {
            headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
          });
          vaptUser = res.ok ? await res.json() : null;
        }
        if (!vaptUser?.email) { setError('Could not get user info.'); return; }
        vaptUserRef.current = vaptUser;

        const password = derivedPassword(vaptUser.email);

        const loginRes = await fetch(`${FLASK_API}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ email: vaptUser.email, password }),
        });

        if (loginRes.ok) {
          const data = await loginRes.json();
          sanctumTokenRef.current = data.token;
          flaskUserRef.current    = data.user;
        } else {
          const regRes = await fetch(`${FLASK_API}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({
              name: vaptUser.name || vaptUser.email,
              email: vaptUser.email,
              password,
              password_confirmation: password,
            }),
          });
          if (regRes.ok) {
            const data = await regRes.json();
            sanctumTokenRef.current = data.token;
            flaskUserRef.current    = data.user;
          } else {
            setError('Mobile scanner auth failed. Is Flask running on port 5000?');
          }
        }
      } catch (e) {
        setError('Cannot connect to Mobile Scanner. Run: python3 app.py sa scanner folder.');
      } finally {
        setReady(true);
        if (iframeLoadedRef.current) sendToIframe();
      }
    };
    run();
  }, [storeUser?.email, token]);

  const handleIframeLoad = () => {
    iframeLoadedRef.current = true;
    if (ready && sanctumTokenRef.current) sendToIframe();
  };

  useEffect(() => {
    const handle = (event) => {
      if (event.origin !== MOBILE_ORIGIN) return;
      if (event.data?.type !== 'MOBILE_READY') return;
      if (sanctumTokenRef.current) sendToIframe();
    };
    window.addEventListener('message', handle);
    return () => window.removeEventListener('message', handle);
  }, []);

  function sendToIframe() {
    const iframe = iframeRef.current;
    if (!iframe?.contentWindow) return;

    // Always use the Laravel role (storeUser.role) as the source of truth
    const laravelRole = storeUser?.role || vaptUserRef.current?.role || 'user';

    iframe.contentWindow.postMessage(
      {
        type:  'VAPT_TOKEN',
        token: sanctumTokenRef.current,
        user:  {
          ...vaptUserRef.current,
          role: laravelRole,
        },
      },
      MOBILE_ORIGIN
    );
  }

  if (!ready) return (
    <div className="flex flex-col items-center justify-center h-full min-h-screen bg-[#0f1117] gap-3 text-gray-400">
      <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      <span className="text-sm">Connecting to Mobile Scanner…</span>
    </div>
  );

  if (error) return (
    <div className="flex flex-col items-center justify-center h-full min-h-screen bg-[#0f1117] gap-4 p-8">
      <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center">
        <span className="text-red-400 text-2xl">⚠</span>
      </div>
      <p className="text-red-400 text-sm text-center max-w-md">{error}</p>
      <div className="bg-[#1a1f2e] border border-gray-700 rounded-xl px-5 py-4 text-gray-400 text-xs leading-7 font-mono">
        cd ~/Desktop/VAPT/mobile-vuln-scanner/scanner<br/>
        source venv/bin/activate<br/>
        python3 app.py
      </div>
      <button
        onClick={() => { syncRan.current = false; setError(null); setReady(false); }}
        className="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition">
        Retry
      </button>
    </div>
  );

  return (
    <iframe
      ref={iframeRef}
      src={MOBILE_ORIGIN}
      onLoad={handleIframeLoad}
      title="Mobile VAPT Scanner"
      style={{ width:'100%', height:'100%', border:'none', minHeight:'calc(100vh - 64px)' }}
      sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation"
    />
  );
}