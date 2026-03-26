import { Link, useNavigate, useLocation, Outlet } from 'react-router-dom';
import { useState } from 'react';
import {
  LayoutDashboard, Users, MonitorCheck, AlertCircle, LogOut,
  ChevronDown, ChevronRight, Shield, Smartphone, Globe, Network, Activity
} from 'lucide-react';
import { useAuthStore } from '../store/authStore';
import { logout } from '../api/authApi';
import toast from 'react-hot-toast';
import Logo from '../components/shared/Logo';

export default function AdminLayout() {
  const { user, clearAuth } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();

  const [openDropdowns, setOpenDropdowns] = useState({});

  const toggleDropdown = (key) => {
    setOpenDropdowns(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleLogout = async () => {
    try {
      await logout();
    } catch {}
    clearAuth();
    toast.success('Logged out');
    navigate('/login');
  };

  const isActive = (path) => location.pathname === path;
  const isGroupActive = (paths) => paths.some(p => location.pathname.startsWith(p));

  const navItems = [
    {
      icon: LayoutDashboard,
      label: 'Dashboard',
      path: '/admin/dashboard',
    },
    {
      icon: Users,
      label: 'Users',
      path: '/admin/users',
    },
    {
      icon: MonitorCheck,
      label: 'Monitors',
      key: 'monitors',
      children: [
        { label: 'All Monitors', path: '/admin/monitors' },
        { label: 'Incidents', path: '/admin/incidents', icon: AlertCircle },
      ],
    },
    {
      icon: Shield,
      label: 'VAPT',
      key: 'vapt',
      children: [
        { label: 'Mobile VAPT', path: '/admin/vapt/mobile', icon: Smartphone },
        { label: 'Web VAPT', path: '/admin/vapt/web', icon: Globe },
        { label: 'Network VAPT', path: '/admin/vapt/network', icon: Network },
      ],
    },
    {
      icon: Activity,
      label: 'System Health',
      path: '/admin/system-health',
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
              <p className="text-gray-500 text-xs">Admin Panel</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            if (item.children) {
              const isOpen = openDropdowns[item.key];
              const groupActive = isGroupActive(item.children.map(c => c.path));

              return (
                <div key={item.key}>
                  {/* Dropdown trigger */}
                  <button
                    onClick={() => toggleDropdown(item.key)}
                    className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition text-left
                      ${groupActive
                        ? 'text-white bg-gray-800'
                        : 'text-gray-400 hover:text-white hover:bg-gray-800'
                      }`}
                  >
                    <item.icon size={20} />
                    <span className="flex-1">{item.label}</span>
                    {isOpen
                      ? <ChevronDown size={16} className="text-gray-500" />
                      : <ChevronRight size={16} className="text-gray-500" />
                    }
                  </button>

                  {/* Dropdown children */}
                  {isOpen && (
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

            // Regular nav item
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
    </div>
  );
}