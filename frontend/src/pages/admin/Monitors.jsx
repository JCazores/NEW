import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { Search, Plus, X, Trash2, ToggleLeft, ToggleRight, Tag } from "lucide-react";
import PaginationCenter from "../../components/PaginationCenter";
import StatusBadge from "../../components/shared/StatusBadge";
import toast from "react-hot-toast";
import {
  getAdminMonitors,
  createMonitor,
  deleteMonitor,
  toggleMonitor,
  getUsers,
  getCategories,
  createCategory,
  deleteCategory,
} from "../../api/adminApi";

const PAGE_SIZE = 10;

const COLOR_STYLES = {
  red:    "bg-red-500/15 text-red-400 border-red-500/25",
  blue:   "bg-blue-500/15 text-blue-400 border-blue-500/25",
  yellow: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25",
  purple: "bg-purple-500/15 text-purple-400 border-purple-500/25",
  gray:   "bg-gray-500/15 text-gray-400 border-gray-500/25",
  green:  "bg-green-500/15 text-green-400 border-green-500/25",
  indigo: "bg-indigo-500/15 text-indigo-400 border-indigo-500/25",
  orange: "bg-orange-500/15 text-orange-400 border-orange-500/25",
  pink:   "bg-pink-500/15 text-pink-400 border-pink-500/25",
};

const COLOR_OPTIONS = [
  { value: "red",    label: "Red"    },
  { value: "blue",   label: "Blue"   },
  { value: "yellow", label: "Yellow" },
  { value: "purple", label: "Purple" },
  { value: "gray",   label: "Gray"   },
  { value: "green",  label: "Green"  },
  { value: "indigo", label: "Indigo" },
  { value: "orange", label: "Orange" },
  { value: "pink",   label: "Pink"   },
];

const FALLBACK_COLORS = {
  Military:     "red",
  Schools:      "blue",
  Government:   "yellow",
  Municipality: "purple",
  Others:       "gray",
};

const SYSTEM_OTHERS = { id: "__others__", name: "Others", color: "gray", system: true };

function CategoryBadge({ category, categories }) {
  const label = category || "Others";
  const cat = categories.find((c) => c.name === label);
  const color = cat?.color || FALLBACK_COLORS[label] || "gray";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${COLOR_STYLES[color] || COLOR_STYLES.gray}`}>
      {label}
    </span>
  );
}

function getAdditionalEmails(m) {
  const raw =
    m?.recipient_emails ?? m?.additional_emails ??
    m?.notification_emails ?? m?.recipients ??
    m?.alert_recipients ?? m?.notification_recipients ?? [];
  if (Array.isArray(raw))
    return raw.map((x) => (x?.email ? x.email : x)).map((x) => (typeof x === "string" ? x.trim() : "")).filter(Boolean);
  if (typeof raw === "string")
    return raw.split(",").map((x) => x.trim()).filter(Boolean);
  return [];
}

function timeAgo(dateString) {
  if (!dateString) return "Never";
  const diff = Math.floor((Date.now() - new Date(dateString).getTime()) / 1000);
  if (diff < 60)    return `${diff}s ago`;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function AdminMonitors() {
  const location = useLocation();

  const [monitors,   setMonitors]   = useState([]);
  const [users,      setUsers]      = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading,    setLoading]    = useState(true);

  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showCatManager, setShowCatManager] = useState(false);
  const [searchQuery,    setSearchQuery]    = useState("");
  const [page,           setPage]           = useState(1);

  const [newCatName,  setNewCatName]  = useState("");
  const [newCatColor, setNewCatColor] = useState("gray");
  const [catSaving,   setCatSaving]   = useState(false);

  const [selectedCategory, setSelectedCategory] = useState(
    () => localStorage.getItem("am_category") || ""
  );
  const handleCategory = (val) => {
    setSelectedCategory(val);
    localStorage.setItem("am_category", val);
    setPage(1);
  };

  const [selectedUser, setSelectedUser] = useState(
    () => localStorage.getItem("am_user") || ""
  );
  const handleUser = (val) => {
    setSelectedUser(val);
    localStorage.setItem("am_user", val);
    setPage(1);
  };

  const [sortOrder, setSortOrder] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    const urlSort = params.get("sortOrder");
    const valid = ["default", "asc", "desc", "up_only", "down_only"];
    if (urlSort && valid.includes(urlSort)) return urlSort;
    return localStorage.getItem("am_sortOrder") || "default";
  });
  const handleSortOrder = (val) => {
    setSortOrder(val);
    localStorage.setItem("am_sortOrder", val);
  };

  const [formData, setFormData] = useState({
    user_id: "", name: "", url: "", additional_emails: "", category: "",
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 3-PHASE NEW MONITOR TRACKING
  // ─────────────────────────────────────────────────────────────────────────
  const [justCreatedId, setJustCreatedId] = useState(null);
  const [popId,         setPopId]         = useState(null);
  const [popStatus,     setPopStatus]     = useState(null);

  const beforeIdsRef     = useRef(null);
  const justCreatedIdRef = useRef(null);
  const popTimerRef      = useRef(null);
  // ─────────────────────────────────────────────────────────────────────────

  const [highlightId, setHighlightId] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get("highlight");
    return id ? Number(id) : null;
  });
  const highlightRef = useRef(null);

  // Scroll highlighted row into view once monitors load
  useEffect(() => {
    if (highlightId && highlightRef.current) {
      highlightRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
      // Clear highlight after 3 seconds
      const t = setTimeout(() => setHighlightId(null), 3000);
      return () => clearTimeout(t);
    }
  }, [highlightId, monitors]);

  // Update highlightId when location changes (e.g. navigating from Dashboard)
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const id = params.get("highlight");
    setHighlightId(id ? Number(id) : null);
  }, [location.search]);
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const urlSort = params.get("sortOrder");
    const valid = ["default", "asc", "desc", "up_only", "down_only"];
    if (urlSort && valid.includes(urlSort)) {
      setSortOrder(urlSort);
      localStorage.setItem("am_sortOrder", urlSort);
    }

    // If coming from Dashboard, clear category/user filters so monitor is always visible
    if (params.get("resetFilters") === "1") {
      setSelectedCategory("");
      localStorage.setItem("am_category", "");
      setSelectedUser("");
      localStorage.setItem("am_user", "");
      setSearchQuery("");
      setPage(1);
    }
  }, [location.search]);

  useEffect(() => {
    fetchMonitors();
    fetchUsers();
    fetchCategories();
    const interval = setInterval(fetchMonitors, 2000);
    return () => {
      clearInterval(interval);
      if (popTimerRef.current) clearTimeout(popTimerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (categories.length > 0 && !formData.category) {
      const others = categories.find((c) => c.name === "Others");
      setFormData((prev) => ({ ...prev, category: others?.name || "Others" }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [categories]);

  const startPopTimer = (id, status) => {
    setPopId(id);
    setPopStatus(status);
    if (popTimerRef.current) clearTimeout(popTimerRef.current);
    popTimerRef.current = setTimeout(() => {
      setPopId(null);
      setPopStatus(null);
    }, 2000);
  };

  const fetchMonitors = async () => {
    try {
      const res = await getAdminMonitors();
      const fresh = res?.data?.data || [];

      if (beforeIdsRef.current !== null && justCreatedIdRef.current === null) {
        const newM = fresh.find((m) => !beforeIdsRef.current.has(m.id));
        if (newM) {
          beforeIdsRef.current = null;
          const st = (newM.last_status || "").toLowerCase().trim();
          if (st === "up" || st === "down") {
            startPopTimer(newM.id, st);
          } else {
            justCreatedIdRef.current = newM.id;
            setJustCreatedId(newM.id);
          }
        }
      }

      if (justCreatedIdRef.current !== null) {
        const tracked = fresh.find((m) => m.id === justCreatedIdRef.current);
        if (tracked) {
          const st = (tracked.last_status || "").toLowerCase().trim();
          if (st === "up" || st === "down") {
            const doneId = justCreatedIdRef.current;
            justCreatedIdRef.current = null;
            setJustCreatedId(null);
            startPopTimer(doneId, st);
          }
        }
      }

      setMonitors(fresh);
    } catch (err) {
      console.error("getAdminMonitors error:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await getUsers();
      setUsers((res?.data?.data || []).filter((u) => u.role === "user"));
    } catch (err) {
      console.error("getUsers error:", err);
    }
  };

  const fetchCategories = async () => {
    try {
      const res = await getCategories();
      const list = res?.data?.data || [];
      const hasOthers = list.some((c) => (c.name || "").toLowerCase() === "others");
      let finalList = hasOthers ? list : [SYSTEM_OTHERS, ...list];
      finalList = finalList.sort((a, b) => {
        if (a.name === "Others") return 1;
        if (b.name === "Others") return -1;
        return a.name.localeCompare(b.name);
      });
      setCategories(finalList);
    } catch (err) {
      console.error("getCategories error:", err);
      setCategories([SYSTEM_OTHERS]);
    }
  };

  const handleAddCategory = async (e) => {
    e.preventDefault();
    if (!newCatName.trim()) return;
    setCatSaving(true);
    try {
      await createCategory({ name: newCatName.trim(), color: newCatColor });
      toast.success(`Category "${newCatName}" added!`);
      setNewCatName("");
      setNewCatColor("gray");
      await fetchCategories();
    } catch (err) {
      const status = err?.response?.status;
      const msg = err?.response?.data?.message || err?.response?.data?.error || err?.message || "Unknown error";
      toast.error(`Failed (${status || "no-status"}): ${msg}`);
    } finally {
      setCatSaving(false);
    }
  };

  const handleDeleteCategory = async (cat) => {
    if (cat?.name === "Others") {
      toast.error(`"Others" can't be deleted.`);
      return;
    }
    const inUse = monitors.filter((m) => (m.category || "Others") === cat.name).length;
    if (!confirm(`Delete category "${cat.name}"?\n\n${inUse} monitor(s) currently use it.\nThey will be moved to "Others".`)) return;
    try {
      await deleteCategory(cat.id);
      toast.success(`Category "${cat.name}" deleted`);
      await fetchCategories();
      await fetchMonitors();
      if (selectedCategory === cat.name) handleCategory("");
    } catch (err) {
      toast.error(err?.response?.data?.message || `Failed to delete category (${err?.response?.status || "no status"})`);
    }
  };

  const filtered = useMemo(() => {
    let list = [...monitors];
    if (selectedUser) {
      const uid = Number(selectedUser);
      list = list.filter((m) => Number(m.user_id) === uid);
    }
    if (selectedCategory) {
      list = list.filter((m) => (m.category || "Others") === selectedCategory);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((m) => {
        const emails = getAdditionalEmails(m).join(",").toLowerCase();
        return (
          (m.name || "").toLowerCase().includes(q) ||
          (m.url || "").toLowerCase().includes(q) ||
          (m.user?.name || "").toLowerCase().includes(q) ||
          (m.user?.email || "").toLowerCase().includes(q) ||
          (m.category || "").toLowerCase().includes(q) ||
          emails.includes(q)
        );
      });
    }
    return list;
  }, [monitors, selectedUser, selectedCategory, searchQuery]);

  // ─── Sorting + Status-only filtering ─────────────────────────────────────
  const sorted = useMemo(() => {
    const isPinned = (m) => m.id === justCreatedId || m.id === popId;

    // up_only / down_only — filter to just that status, pinned items always included
    if (sortOrder === "up_only" || sortOrder === "down_only") {
      const target = sortOrder === "up_only" ? "up" : "down";
      return filtered.filter(
        (m) => isPinned(m) || (m.last_status || "").toLowerCase() === target
      );
    }

    // Default / asc / desc — original logic unchanged
    const list = [...filtered];
    const rankUp   = (m) => { if (isPinned(m)) return 0; return (m.last_status || "").toLowerCase() === "up"   ? 1 : 2; };
    const rankDown = (m) => { if (isPinned(m)) return 0; return (m.last_status || "").toLowerCase() === "down" ? 1 : 2; };

    if (sortOrder === "default") {
      return [...list.filter(isPinned), ...list.filter((m) => !isPinned(m))];
    }

    list.sort((a, b) => {
      const ra = sortOrder === "asc" ? rankUp(a) : rankDown(a);
      const rb = sortOrder === "asc" ? rankUp(b) : rankDown(b);
      if (ra !== rb) return ra - rb;
      return (a.name || "").toLowerCase().localeCompare((b.name || "").toLowerCase());
    });

    return list;
  }, [filtered, sortOrder, justCreatedId, popId]);
  // ─────────────────────────────────────────────────────────────────────────

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pageRows   = useMemo(
    () => sorted.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE),
    [sorted, safePage]
  );

  useEffect(() => { if (page !== safePage) setPage(safePage); }, [safePage]);

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      const extraEmails = formData.additional_emails
        ? formData.additional_emails.split(",").map((x) => x.trim()).filter(Boolean)
        : [];

      beforeIdsRef.current = new Set(monitors.map((m) => m.id));

      await createMonitor({
        user_id:                formData.user_id,
        name:                   formData.name,
        url:                    formData.url,
        category:               formData.category || "Others",
        check_interval_seconds: 2,
        recipient_emails:       extraEmails,
      });

      setShowCreateForm(false);
      const others = categories.find((c) => c.name === "Others");
      setFormData({
        user_id: "",
        name: "",
        url: "",
        additional_emails: "",
        category: others?.name || "Others",
      });

      fetchMonitors();
    } catch (err) {
      console.error(err);
      beforeIdsRef.current = null;
      alert(err?.response?.data?.message || "Failed to create monitor");
    }
  };

  const handleToggle = async (m) => {
    try { await toggleMonitor(m.id); await fetchMonitors(); }
    catch (err) { console.error(err); alert("Failed to toggle monitor"); }
  };

  const handleDelete = async (id) => {
    if (!confirm("Delete this monitor?")) return;
    try { await deleteMonitor(id); await fetchMonitors(); }
    catch (err) { console.error(err); alert("Failed to delete monitor"); }
  };

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold text-white">Monitors</h1>
        <div className="flex gap-3">
          <button
            onClick={() => setShowCatManager(true)}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition"
          >
            <Tag size={18} /> Manage Categories
          </button>

          <button
            onClick={() => setShowCreateForm((v) => !v)}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition"
          >
            {showCreateForm ? <X size={18} /> : <Plus size={18} />}
            {showCreateForm ? "Cancel" : "Create Monitor"}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4 mb-6">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
          <input
            value={searchQuery}
            onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
            placeholder="Search monitor, URL, user, or email..."
            className="w-full pl-10 pr-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 focus:border-green-500 outline-none"
          />
        </div>

        <select
          value={selectedCategory}
          onChange={(e) => handleCategory(e.target.value)}
          className="px-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 focus:border-green-500 outline-none"
        >
          <option value="">All Categories</option>
          {categories.map((cat) => (
            <option key={cat.id} value={cat.name}>{cat.name}</option>
          ))}
        </select>

        <select
          value={selectedUser}
          onChange={(e) => handleUser(e.target.value)}
          className="w-44 flex-shrink-0 px-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 focus:border-green-500 outline-none"
        >
          <option value="">All Users</option>
          {users.map((u) => (
            <option key={u.id} value={u.id}>{u.name} ({u.email})</option>
          ))}
        </select>

        <select
          value={sortOrder}
          onChange={(e) => handleSortOrder(e.target.value)}
          className="w-36 flex-shrink-0 px-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 focus:border-green-500 outline-none cursor-pointer"
        >
          <option value="default">Default</option>
          <option value="asc">Ascending</option>
          <option value="desc">Descending</option>
          <option value="up_only">🟢 Up Only</option>
          <option value="down_only">🔴 Down Only</option>
        </select>
      </div>

      {/* Create Modal */}
      {showCreateForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-900 rounded-xl p-6 w-full max-w-2xl border border-gray-800 max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-semibold text-white mb-4">Create New Monitor</h2>

            <form onSubmit={handleCreate} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Assign to User *</label>
                  <select
                    value={formData.user_id}
                    onChange={(e) => setFormData({ ...formData, user_id: e.target.value })}
                    className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
                    required
                  >
                    <option value="">Select user</option>
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>{u.name} ({u.email})</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-2">Monitor Name *</label>
                  <input
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
                    placeholder="Spotify"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">Category *</label>
                <select
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
                  required
                >
                  <option value="">Select category</option>
                  {categories.map((cat) => (
                    <option key={cat.id} value={cat.name}>{cat.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">URL *</label>
                <input
                  type="url"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
                  placeholder="https://example.com"
                  required
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">Additional Emails (comma separated)</label>
                <input
                  value={formData.additional_emails}
                  onChange={(e) => setFormData({ ...formData, additional_emails: e.target.value })}
                  className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
                  placeholder="a@gmail.com, b@gmail.com"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg"
                >
                  Close
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg"
                >
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Categories Modal */}
      {showCatManager && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-900 rounded-xl p-6 w-full max-w-lg border border-gray-800 max-h-[85vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-5">
              <h2 className="text-xl font-semibold text-white">Manage Categories</h2>
              <button onClick={() => setShowCatManager(false)} className="text-gray-400 hover:text-white">
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleAddCategory} className="mb-6">
              <p className="text-sm text-gray-400 mb-3">Add New Category</p>
              <div className="flex gap-3">
                <input
                  value={newCatName}
                  onChange={(e) => setNewCatName(e.target.value)}
                  placeholder="e.g. Partnership"
                  maxLength={50}
                  required
                  className="flex-1 px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
                />
                <select
                  value={newCatColor}
                  onChange={(e) => setNewCatColor(e.target.value)}
                  className="px-3 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
                >
                  {COLOR_OPTIONS.map((c) => (
                    <option key={c.value} value={c.value}>{c.label}</option>
                  ))}
                </select>
                <button
                  type="submit"
                  disabled={catSaving}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition disabled:opacity-50"
                >
                  <Plus size={18} />
                </button>
              </div>

              {newCatName && (
                <div className="mt-3 flex items-center gap-2">
                  <span className="text-xs text-gray-400">Preview:</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${COLOR_STYLES[newCatColor] || COLOR_STYLES.gray}`}>
                    {newCatName}
                  </span>
                </div>
              )}
            </form>

            <p className="text-sm text-gray-400 mb-3">Existing Categories</p>
            <div className="space-y-2">
              {categories.map((cat) => {
                const inUse = monitors.filter((m) => (m.category || "Others") === cat.name).length;
                const isOthers = cat.name === "Others";
                return (
                  <div
                    key={cat.id}
                    className="flex items-center justify-between px-4 py-3 bg-gray-800 rounded-lg border border-gray-700"
                  >
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${COLOR_STYLES[cat.color] || COLOR_STYLES.gray}`}>
                      {cat.name}
                    </span>

                    <div className="flex items-center gap-3 text-xs text-gray-500">
                      <span>{inUse} monitor{inUse !== 1 ? "s" : ""}</span>
                      <button
                        disabled={isOthers}
                        onClick={() => handleDeleteCategory(cat)}
                        className={`p-1.5 rounded transition ${
                          isOthers
                            ? "opacity-40 cursor-not-allowed text-gray-500"
                            : "text-red-400 hover:bg-red-500/10"
                        }`}
                        title={isOthers ? `"Others" can't be deleted` : "Delete"}
                      >
                        <Trash2 size={15} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="rounded-2xl border border-gray-800 bg-gradient-to-b from-gray-950 to-gray-900 shadow-lg overflow-hidden">
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full min-w-max text-left">
            <thead className="sticky top-0 bg-gray-950/95 backdrop-blur border-b border-gray-800">
              <tr className="text-xs uppercase tracking-wider text-gray-400">
                <th className="px-5 py-3">Monitor</th>
                <th className="px-5 py-3">Category</th>
                <th className="px-5 py-3">User</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Uptime</th>
                <th className="px-5 py-3">Response</th>
                <th className="px-5 py-3">SSL</th>
                <th className="px-5 py-3">Last Check</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>

            <tbody>
              {loading ? (
                <tr>
                  <td className="px-5 py-6 text-gray-400" colSpan={9}>Loading monitors...</td>
                </tr>
              ) : sorted.length === 0 ? (
                <tr>
                  <td className="px-5 py-6 text-gray-400" colSpan={9}>No monitors found</td>
                </tr>
              ) : pageRows.map((m) => {
                const isChecking = m.id === justCreatedId;
                const isPop = m.id === popId;
                const isUp = popStatus === "up";
                const extra = getAdditionalEmails(m);
                const sslText = m.url?.startsWith("https://") && m.ssl_days_remaining != null ? `${m.ssl_days_remaining}d` : "—";

                const isHighlighted = m.id === highlightId;
                const rowClass = isChecking
                  ? "bg-yellow-500/10 border-l-4 border-l-yellow-500"
                  : isPop
                  ? isUp ? "bg-green-500/20 border-l-4 border-l-green-400"
                         : "bg-red-500/20 border-l-4 border-l-red-400"
                  : isHighlighted
                  ? "bg-blue-500/20 border-l-4 border-l-blue-400 ring-1 ring-blue-400/30"
                  : "";

                return (
                  <tr
                    key={m.id}
                    ref={isHighlighted ? highlightRef : null}
                    className={`border-b border-gray-900 hover:bg-gray-900/40 transition-all duration-500 ${rowClass}`}
                  >
                    <td className="px-5 py-4">
                      <div className={`font-semibold ${isChecking ? "text-yellow-300" : isPop ? (isUp ? "text-green-300" : "text-red-300") : "text-white"}`}>
                        {m.name}
                        {isChecking && <span className="ml-2 text-xs text-yellow-400 font-normal animate-pulse">● checking...</span>}
                        {isPop && <span className={`ml-2 text-xs font-semibold animate-pulse ${isUp ? "text-green-400" : "text-red-400"}`}>● {isUp ? "UP" : "DOWN"}</span>}
                      </div>
                      <div className="text-gray-500 text-sm truncate max-w-[260px]">{m.url}</div>
                    </td>

                    <td className="px-5 py-4">
                      <CategoryBadge category={m.category} categories={categories} />
                    </td>

                    <td className="px-5 py-4">
                      <div className="text-white font-semibold">{m.user?.name || "—"}</div>
                      <div className="text-xs text-gray-400">{m.user?.email || ""}</div>

                      {extra.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {extra.slice(0, 2).map((email, idx) => (
                            <span
                              key={idx}
                              className="text-xs text-green-300 bg-green-500/10 border border-green-500/20 px-2 py-0.5 rounded-full"
                            >
                              {email}
                            </span>
                          ))}
                          {extra.length > 2 && <span className="text-xs text-gray-500">+{extra.length - 2} more</span>}
                        </div>
                      )}
                    </td>

                    <td className="px-5 py-4"><StatusBadge status={m.last_status} /></td>

                    <td className="px-5 py-4 text-green-400 font-semibold">
                      {typeof m.uptime_percentage === "number"
                        ? `${m.uptime_percentage.toFixed(2)}%`
                        : `${m.uptime_percentage || 0}%`}
                    </td>

                    <td className="px-5 py-4 text-white font-semibold">
                      {m.last_response_time_ms ? `${m.last_response_time_ms}ms` : "—"}
                    </td>

                    <td className="px-5 py-4 text-white font-semibold">
                      {sslText === "—" ? "—" : <span>🔒 <span className="text-green-400">{sslText}</span></span>}
                    </td>

                    <td className="px-5 py-4 text-white">{timeAgo(m.last_checked_at)}</td>

                    <td className="px-5 py-4">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleToggle(m)}
                          className="p-2 text-yellow-400 hover:bg-yellow-500/10 rounded transition"
                          title={m.is_active ? "Pause" : "Resume"}
                        >
                          {m.is_active ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}
                        </button>

                        <button
                          onClick={() => handleDelete(m.id)}
                          className="p-2 text-red-400 hover:bg-red-500/10 rounded transition"
                          title="Delete"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <PaginationCenter
          page={safePage}
          totalPages={totalPages}
          onPrev={() => setPage((p) => Math.max(1, p - 1))}
          onNext={() => setPage((p) => Math.min(totalPages, p + 1))}
        />
      </div>
    </div>
  );
}