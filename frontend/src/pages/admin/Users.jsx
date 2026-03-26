import { useState, useEffect } from 'react';
import { Trash2, Mail, ShieldCheck, Lock, Unlock, MonitorCheck, Shield, Activity, Pencil, Check, X } from 'lucide-react';
import toast from 'react-hot-toast';
import {
  getUsers, createUser, deleteUser,
  updateStatus, resendOtp, updatePermissions
} from '../../api/adminApi';

const ALL_PERMISSIONS = [
  {
    key:         'monitors',
    label:       'Monitors',
    description: 'My Monitors & Incidents',
    icon:        MonitorCheck,
    color:       'blue',
  },
  {
    key:         'vapt',
    label:       'VAPT',
    description: 'Mobile, Web & Network VAPT',
    icon:        Shield,
    color:       'purple',
  },
];

const COLOR = {
  blue:   { bg: 'bg-blue-500/15',   border: 'border-blue-500/40',   text: 'text-blue-400',   dot: 'bg-blue-400'   },
  purple: { bg: 'bg-purple-500/15', border: 'border-purple-500/40', text: 'text-purple-400', dot: 'bg-purple-400' },
  orange: { bg: 'bg-orange-500/15', border: 'border-orange-500/40', text: 'text-orange-400', dot: 'bg-orange-400' },
};

// Small visual pill for a single permission
function PermPill({ perm, granted }) {
  const c = COLOR[perm.color];
  const Icon = perm.icon;
  return (
    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium
      ${granted ? `${c.bg} ${c.border} ${c.text}` : 'bg-gray-800/60 border-gray-700 text-gray-600'}`}
    >
      <Icon size={11} />
      {perm.label}
      {!granted && <Lock size={10} className="ml-0.5 text-gray-600" />}
    </div>
  );
}

export default function Users() {
  const [users, setUsers]               = useState([]);
  const [loading, setLoading]           = useState(true);
  const [showModal, setShowModal]       = useState(false);
  const [email, setEmail]               = useState('');
  const [permModal, setPermModal]       = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedPerms, setSelectedPerms] = useState([]);
  const [savingPerms, setSavingPerms]   = useState(false);

  useEffect(() => {
    fetchUsers();
    const interval = setInterval(fetchUsers, 2000);
    return () => clearInterval(interval);
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await getUsers();
      setUsers(res.data.data);
    } catch {
      toast.error('Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      await createUser({ email });
      toast.success('User added! OTP sent to their email.');
      setEmail('');
      setShowModal(false);
      fetchUsers();
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to add user');
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this user?')) return;
    try {
      await deleteUser(id);
      toast.success('User deleted');
      fetchUsers();
    } catch {
      toast.error('Failed to delete user');
    }
  };

  const handleUpdateStatus = async (id, newStatus) => {
    try {
      await updateStatus(id, { status: newStatus });
      toast.success('Status updated');
      fetchUsers();
    } catch {
      toast.error('Failed to update status');
    }
  };

  const handleResendOtp = async (userEmail) => {
    try {
      await resendOtp({ email: userEmail });
      toast.success('OTP resent!');
    } catch {
      toast.error('Failed to resend OTP');
    }
  };

  const openPermModal = (user) => {
    setSelectedUser(user);
    setSelectedPerms(user.permissions ?? []);
    setPermModal(true);
  };

  const togglePerm = (key) => {
    setSelectedPerms(prev =>
      prev.includes(key) ? prev.filter(p => p !== key) : [...prev, key]
    );
  };

  const handleSavePerms = async () => {
    setSavingPerms(true);
    try {
      await updatePermissions(selectedUser.id, selectedPerms);
      toast.success(`Access updated for ${selectedUser.name}`);
      setPermModal(false);
      fetchUsers();
    } catch {
      toast.error('Failed to update permissions');
    } finally {
      setSavingPerms(false);
    }
  };

  const getStatusBadge = (status, isOnline) => {
    const cfg = {
      pending:    { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Pending OTP' },
      registered: { bg: 'bg-blue-500/20',   text: 'text-blue-400',   label: 'Registered'  },
      active:     { bg: 'bg-green-500/20',  text: 'text-green-400',  label: 'Active'       },
      disabled:   { bg: 'bg-red-500/20',    text: 'text-red-400',    label: 'Disabled'     },
    }[status] || { bg: 'bg-blue-500/20', text: 'text-blue-400', label: 'Registered' };

    return (
      <div className="flex items-center gap-2">
        <span className={`text-xs px-2 py-1 rounded-full ${cfg.bg} ${cfg.text}`}>{cfg.label}</span>
        {status !== 'pending' && status !== 'disabled' && (
          <span className="flex items-center gap-1 text-xs text-gray-500">
            {isOnline
              ? <><span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />Online</>
              : <><span className="w-2 h-2 bg-gray-600 rounded-full" />Offline</>
            }
          </span>
        )}
      </div>
    );
  };

  const grantedCount = (user) => (user.permissions ?? []).length;

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-white">User Management</h1>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-green-500 hover:bg-green-400 text-black font-semibold rounded-lg transition"
        >
          <Mail size={20} />
          Add User by Email
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-max">
            <thead className="bg-gray-800/50">
              <tr>
                <th className="text-left text-gray-400 px-6 py-4 font-medium">Name</th>
                <th className="text-left text-gray-400 px-6 py-4 font-medium">Email</th>
                <th className="text-left text-gray-400 px-6 py-4 font-medium">Status</th>
                <th className="text-left text-gray-400 px-6 py-4 font-medium">Monitors</th>
                <th className="text-left text-gray-400 px-6 py-4 font-medium">Page Access</th>
                <th className="text-left text-gray-400 px-6 py-4 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.filter(u => u.role !== 'admin').map(user => (
                <tr key={user.id} className="border-t border-gray-800 hover:bg-gray-800/30">
                  <td className="px-6 py-4 text-white font-medium">{user.name}</td>
                  <td className="px-6 py-4 text-gray-400">{user.email}</td>
                  <td className="px-6 py-4">{getStatusBadge(user.status, user.is_online)}</td>
                  <td className="px-6 py-4 text-gray-400">{user.monitors_count ?? 0}</td>

                  {/* ── Page Access column ── */}
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2 flex-wrap">
                      {ALL_PERMISSIONS.map(perm => (
                        <PermPill
                          key={perm.key}
                          perm={perm}
                          granted={(user.permissions ?? []).includes(perm.key)}
                        />
                      ))}
                      {/* Edit access button */}
                      <button
                        onClick={() => openPermModal(user)}
                        title="Edit page access"
                        className="flex items-center gap-1 px-2.5 py-1 rounded-full bg-gray-700 hover:bg-teal-500/20 hover:text-teal-400 border border-gray-600 hover:border-teal-500/50 text-gray-400 text-xs font-medium transition"
                      >
                        <Pencil size={11} />
                        Edit
                      </button>
                    </div>
                  </td>

                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      {user.status === 'pending' && (
                        <button
                          onClick={() => handleResendOtp(user.email)}
                          className="p-2 text-blue-400 hover:bg-blue-500/10 rounded transition"
                          title="Resend OTP"
                        >
                          <Mail size={16} />
                        </button>
                      )}
                      <select
                        value={user.status}
                        onChange={(e) => handleUpdateStatus(user.id, e.target.value)}
                        className="px-2 py-1 bg-gray-800 text-white text-xs rounded border border-gray-700 focus:border-green-500 outline-none"
                      >
                        <option value="pending">Pending</option>
                        <option value="registered">Registered</option>
                        <option value="active">Active</option>
                        <option value="disabled">Disabled</option>
                      </select>
                      <button
                        onClick={() => handleDelete(user.id)}
                        className="p-2 text-red-400 hover:bg-red-500/10 rounded transition"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Add User Modal ── */}
      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 w-full max-w-md">
            <h3 className="text-white text-lg font-semibold mb-4">Add User by Email</h3>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="text-gray-400 text-sm">User Gmail Address</label>
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required
                  pattern=".*@gmail\.com$"
                  title="Must be a Gmail address"
                  placeholder="user@gmail.com"
                  className="w-full mt-1 px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
                />
                <p className="text-gray-500 text-xs mt-2">
                  User will receive an OTP when they try to login for the first time.
                </p>
              </div>
              <div className="flex gap-3">
                <button type="button" onClick={() => setShowModal(false)}
                  className="flex-1 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg transition">
                  Cancel
                </button>
                <button type="submit"
                  className="flex-1 py-2 bg-green-500 hover:bg-green-400 text-black font-semibold rounded-lg transition">
                  Add User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Permissions Modal ── */}
      {permModal && selectedUser && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-md shadow-2xl overflow-hidden">

            {/* Header */}
            <div className="bg-gradient-to-r from-teal-600/20 to-blue-600/10 border-b border-gray-800 px-6 py-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-teal-500/20 border border-teal-500/30 flex items-center justify-center">
                    <ShieldCheck size={20} className="text-teal-400" />
                  </div>
                  <div>
                    <h3 className="text-white font-semibold text-base">Manage Page Access</h3>
                    <p className="text-gray-400 text-xs mt-0.5">
                      {selectedUser.name} · {selectedUser.email}
                    </p>
                  </div>
                </div>
                <button onClick={() => setPermModal(false)} className="text-gray-500 hover:text-white transition">
                  <X size={20} />
                </button>
              </div>

              {/* Access summary bar */}
              <div className="mt-4 flex items-center gap-2">
                <div className="flex-1 bg-gray-800 rounded-full h-1.5 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-teal-500 to-blue-500 rounded-full transition-all duration-500"
                    style={{ width: `${(selectedPerms.length / ALL_PERMISSIONS.length) * 100}%` }}
                  />
                </div>
                <span className="text-xs text-gray-400 whitespace-nowrap">
                  {selectedPerms.length} / {ALL_PERMISSIONS.length} pages granted
                </span>
              </div>
            </div>

            {/* Permission cards */}
            <div className="p-6 space-y-3">
              <p className="text-gray-500 text-xs mb-4">
                Toggle access for each section. <span className="text-white">Dashboard</span> is always visible and cannot be removed.
              </p>

              {/* Always-on Dashboard card */}
              <div className="flex items-center gap-4 p-4 rounded-xl border border-green-500/20 bg-green-500/5">
                <div className="w-9 h-9 rounded-lg bg-green-500/15 flex items-center justify-center flex-shrink-0">
                  <Check size={18} className="text-green-400" />
                </div>
                <div className="flex-1">
                  <p className="text-white text-sm font-medium">Dashboard</p>
                  <p className="text-gray-500 text-xs">Always accessible to all users</p>
                </div>
                <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-500/15 border border-green-500/30">
                  <Unlock size={13} className="text-green-400" />
                  <span className="text-green-400 text-xs font-medium">Always On</span>
                </div>
              </div>

              {/* Toggleable permission cards */}
              {ALL_PERMISSIONS.map(perm => {
                const granted  = selectedPerms.includes(perm.key);
                const c        = COLOR[perm.color];
                const Icon     = perm.icon;
                return (
                  <button
                    key={perm.key}
                    onClick={() => togglePerm(perm.key)}
                    className={`w-full flex items-center gap-4 p-4 rounded-xl border transition text-left
                      ${granted
                        ? `${c.bg} ${c.border}`
                        : 'bg-gray-800/40 border-gray-700 hover:border-gray-500'
                      }`}
                  >
                    {/* Icon */}
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0
                      ${granted ? `${c.bg} border ${c.border}` : 'bg-gray-700/50'}`}>
                      <Icon size={18} className={granted ? c.text : 'text-gray-500'} />
                    </div>

                    {/* Label */}
                    <div className="flex-1">
                      <p className={`text-sm font-medium ${granted ? 'text-white' : 'text-gray-400'}`}>
                        {perm.label}
                      </p>
                      <p className="text-gray-500 text-xs mt-0.5">{perm.description}</p>
                    </div>

                    {/* Toggle pill */}
                    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border transition
                      ${granted
                        ? `${c.bg} ${c.border}`
                        : 'bg-gray-700/50 border-gray-600'
                      }`}
                    >
                      {granted
                        ? <><Unlock size={13} className={c.text} /><span className={`${c.text} text-xs font-medium`}>Granted</span></>
                        : <><Lock   size={13} className="text-gray-500" /><span className="text-gray-500 text-xs font-medium">Locked</span></>
                      }
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Footer */}
            <div className="px-6 pb-6 flex gap-3">
              <button
                onClick={() => setPermModal(false)}
                className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-white rounded-xl transition font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleSavePerms}
                disabled={savingPerms}
                className="flex-1 py-2.5 bg-teal-500 hover:bg-teal-400 text-black font-semibold rounded-xl transition disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {savingPerms ? (
                  <>Saving…</>
                ) : (
                  <><ShieldCheck size={16} /> Save Access</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}