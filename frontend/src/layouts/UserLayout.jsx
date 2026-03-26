import { Link, useNavigate, useLocation, Outlet } from 'react-router-dom';
import { useState, useEffect, useRef } from 'react';
import {
  LayoutDashboard, MonitorCheck, AlertCircle, LogOut,
  ChevronDown, ChevronRight, Shield, Smartphone, Globe,
  Network, Activity, Lock, ShieldCheck
} from 'lucide-react';
import { useAuthStore } from '../store/authStore';
import { logout } from '../api/authApi';
import { getMe } from '../api/authApi';
import toast from 'react-hot-toast';
import Logo from '../components/shared/Logo';

const POLL_INTERVAL = 1500; // check every 1.5 seconds

export default function UserLayout() {
  const { user, clearAuth, updateUser } = useAuthStore();
  const navigate                        = useNavigate();
  const location                        = useLocation();
  const [openDropdowns, setOpenDropdowns] = useState({});
  const [lockedModal, setLockedModal]     = useState(null);
  const prevPermsRef                      = useRef(JSON.stringify(user?.permissions ?? []));

  // ── Real-time permission polling ──────────────────────────────────────────
  useEffect(() => {
    const poll = async () => {
      try {
        const res         = await getMe();
        const freshUser   = res.data;
        const freshPerms  = JSON.stringify(freshUser?.permissions ?? []);
        const prevPerms   = prevPermsRef.current;

        // Only update store + notify if permissions actually changed
        if (freshPerms !== prevPerms) {
          prevPermsRef.current = freshPerms;
          updateUser(freshUser);

          const added   = (freshUser.permissions ?? []).filter(p => !JSON.parse(prevPerms).includes(p));
          const removed = JSON.parse(prevPerms).filter(p => !(freshUser.permissions ?? []).includes(p));

          const LABELS = { monitors: 'Monitors', vapt: 'VAPT', system_health: 'System Health' };

          added.forEach(p =>
            toast.success(`✅ Access granted: ${LABELS[p] ?? p}`, { duration: 4000 })
          );
          removed.forEach(p =>
            toast.error(`🔒 Access removed: ${LABELS[p] ?? p}`, { duration: 4000 })
          );
        }
      } catch {
        // silently ignore network errors during polling
      }
    };

    const interval = setInterval(poll, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [updateUser]);
  // ─────────────────────────────────────────────────────────────────────────

  const toggleDropdown = (key) =>
    setOpenDropdowns(prev => ({ ...prev, [key]: !prev[key] }));

  const handleLogout = async () => {
    try { await logout(); } catch {}
    clearAuth();
    toast.success('Logged out');
    navigate('/login');
  };

  const isActive      = (path)  => location.pathname === path;
  const isGroupActive = (paths) => paths.some(p => location.pathname.startsWith(p));

  const can = (permission) => {
    if (!user) return false;
    if (user.role === 'admin') return true;
    return (user.permissions ?? []).includes(permission);
  };

  const navItems = [
    {
      icon:       LayoutDashboard,
      label:      'Dashboard',
      path:       '/user/dashboard',
      permission: null,
    },
    {
      icon:       MonitorCheck,
      label:      'My Monitors',
      key:        'monitors',
      permission: 'monitors',
      children: [
        { label: 'All Monitors', path: '/user/monitors' },
        { label: 'Incidents',    path: '/user/incidents', icon: AlertCircle },
      ],
    },
    {
      icon:       Shield,
      label:      'VAPT',
      key:        'vapt',
      permission: 'vapt',
      children: [
        { label: 'Mobile VAPT',  path: '/user/vapt/mobile',  icon: Smartphone },
        { label: 'Web VAPT',     path: '/user/vapt/web',     icon: Globe      },
        { label: 'Network VAPT', path: '/user/vapt/network', icon: Network    },
      ],
    },
    {
      icon:       Activity,
      label:      'System Health',
      path:       '/user/system-health',
      permission: null, // always accessible to all users
    },
  ];

  return (
    <div className="min-h-screen bg-gray-950 flex">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="p-6 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <Logo size="default" />
            <div>
              <h1 className="text-white text-xl font-bold">ServerSentinel</h1>
              <p className="text-gray-500 text-xs">User Panel</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const locked = item.permission !== null && !can(item.permission);

            if (item.children) {
              const isOpen      = openDropdowns[item.key];
              const groupActive = !locked && isGroupActive(item.children.map(c => c.path));

              return (
                <div key={item.key}>
                  <button
                    onClick={() => {
                      if (locked) { setLockedModal(item.label); return; }
                      toggleDropdown(item.key);
                    }}
                    className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition text-left
                      ${locked
                        ? 'text-gray-600 cursor-pointer hover:bg-gray-800/40'
                        : groupActive
                          ? 'text-white bg-gray-800'
                          : 'text-gray-400 hover:text-white hover:bg-gray-800'
                      }`}
                  >
                    <item.icon size={20} className={locked ? 'text-gray-600' : ''} />
                    <span className="flex-1">{item.label}</span>
                    {locked ? (
                      <Lock size={14} className="text-gray-600" />
                    ) : isOpen ? (
                      <ChevronDown  size={16} className="text-gray-500" />
                    ) : (
                      <ChevronRight size={16} className="text-gray-500" />
                    )}
                  </button>

                  {!locked && isOpen && (
                    <div className="ml-4 mt-1 space-y-1 border-l border-gray-700 pl-3">
                      {item.children.map((child) => (
                        <Link
                          key={child.path}
                          to={child.path}
                          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition
                            ${isActive(child.path)
                              ? 'text-white bg-gray-700'
                              : 'text-gray-400 hover:text-white hover:bg-gray-800'
                            }`}
                        >
                          {child.icon && <child.icon size={16} />}
                          <span>{child.label}</span>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              );
            }

            if (locked) {
              return (
                <button
                  key={item.label}
                  onClick={() => setLockedModal(item.label)}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition text-left text-gray-600 hover:bg-gray-800/40"
                >
                  <item.icon size={20} />
                  <span className="flex-1">{item.label}</span>
                  <Lock size={14} className="text-gray-600" />
                </button>
              );
            }

            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg transition
                  ${isActive(item.path)
                    ? 'text-white bg-gray-800'
                    : 'text-gray-400 hover:text-white hover:bg-gray-800'
                  }`}
              >
                <item.icon size={20} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="p-4 border-t border-gray-800">
          <div className="flex items-center gap-3 px-4 py-3 mb-2">
            <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center text-black font-bold">
              {user?.name?.[0]?.toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-white text-sm font-medium truncate">{user?.name}</p>
              <p className="text-gray-500 text-xs truncate">{user?.email}</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-4 py-2 text-gray-400 hover:text-red-400 hover:bg-gray-800 rounded-lg transition"
          >
            <LogOut size={18} />
            <span>Logout</span>
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <Outlet />
      </div>

      {/* Locked Section Modal */}
      {lockedModal && (
        <div
          className="fixed inset-0 bg-black/70 flex items-center justify-center z-50"
          onClick={() => setLockedModal(null)}
        >
          <div
            className="bg-gray-900 border border-gray-700 rounded-2xl p-8 w-full max-w-sm text-center shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex justify-center mb-5">
              <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center">
                <Lock size={28} className="text-red-400" />
              </div>
            </div>
            <h3 className="text-white text-xl font-bold mb-2">Access Restricted</h3>
            <p className="text-gray-400 text-sm mb-1">You don't have access to</p>
            <p className="text-white font-semibold text-base mb-4">{lockedModal}</p>
            <p className="text-gray-500 text-xs mb-6">
              Please contact your administrator to request access to this section.
            </p>
            <button
              onClick={() => setLockedModal(null)}
              className="w-full py-2.5 bg-gray-800 hover:bg-gray-700 text-white rounded-xl transition font-medium"
            >
              Got it
            </button>
          </div>
        </div>
      )}
    </div>
  );
}