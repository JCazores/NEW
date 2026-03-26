import { useState, useEffect, useRef, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { Search } from "lucide-react";
import StatusBadge from "../../components/shared/StatusBadge";
import PaginationCenter from "../../components/PaginationCenter";
import { getUserMonitors, getCategories } from "../../api/userApi";

const PAGE_SIZE = 13;

const COLOR_STYLES = {
  red:    "bg-red-500/15 text-red-400 border-red-500/30",
  blue:   "bg-blue-500/15 text-blue-400 border-blue-500/30",
  yellow: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  purple: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  gray:   "bg-gray-500/15 text-gray-400 border-gray-500/30",
  green:  "bg-green-500/15 text-green-400 border-green-500/30",
  indigo: "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
  orange: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  pink:   "bg-pink-500/15 text-pink-400 border-pink-500/30",
};

const FALLBACK_COLORS = {
  Military: "red", Schools: "blue", Government: "yellow",
  Municipality: "purple", Others: "gray",
};

const SYSTEM_OTHERS = { id: "__others__", name: "Others", color: "gray", system: true };

export default function UserMonitors() {
  const [monitors,   setMonitors]   = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [search,     setSearch]     = useState("");

  const [sortOrder, setSortOrder] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    const urlSort = params.get("sortOrder");
    const valid = ["default", "asc", "desc", "up_only", "down_only"];
    if (urlSort && valid.includes(urlSort)) return urlSort;
    return localStorage.getItem("um_sortOrder") || "default";
  });
  const handleSortOrder = (val) => {
    setSortOrder(val);
    localStorage.setItem("um_sortOrder", val);
  };

  const [selectedCategory, setSelectedCategory] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("resetFilters") === "1") return "";
    return localStorage.getItem("um_category") || "";
  });
  const handleCategory = (val) => {
    setSelectedCategory(val);
    localStorage.setItem("um_category", val);
    if (!val) { setSortOrder("default"); localStorage.setItem("um_sortOrder", "default"); }
    setPage(1);
  };

  const [page,          setPage]          = useState(1);
  const [highlightId,   setHighlightId]   = useState(null);
  const highlightRef                      = useRef(null);
  const jumpedRef                         = useRef(false);
  const [searchParams]                    = useSearchParams();
  const [justCreatedId, setJustCreatedId] = useState(null);
  const [popId,         setPopId]         = useState(null);
  const [popStatus,     setPopStatus]     = useState(null);
  const beforeIdsRef                      = useRef(null);
  const justCreatedIdRef                  = useRef(null);
  const popTimerRef                       = useRef(null);

  useEffect(() => {
    window.__trackNewMonitor = (idSet) => { beforeIdsRef.current = idSet; };
    return () => { delete window.__trackNewMonitor; };
  }, []);

  useEffect(() => {
    const id = searchParams.get("highlight");
    if (id) {
      setHighlightId(Number(id));
      jumpedRef.current = false;
      const t = setTimeout(() => setHighlightId(null), 3000);
      return () => clearTimeout(t);
    }
  }, [searchParams]);

  useEffect(() => {
    const urlSort = searchParams.get("sortOrder");
    const valid = ["default", "asc", "desc", "up_only", "down_only"];
    if (urlSort && valid.includes(urlSort)) { setSortOrder(urlSort); localStorage.setItem("um_sortOrder", urlSort); }
    if (searchParams.get("resetFilters") === "1") {
      setSelectedCategory(""); localStorage.setItem("um_category", ""); setSearch(""); setPage(1);
    }
  }, [searchParams]);

  const startPopTimer = (id, status) => {
    setPopId(id); setPopStatus(status);
    if (popTimerRef.current) clearTimeout(popTimerRef.current);
    popTimerRef.current = setTimeout(() => { setPopId(null); setPopStatus(null); }, 2000);
  };

  const fetchMonitors = async () => {
    try {
      const res   = await getUserMonitors();
      const fresh = res?.data?.data || [];
      if (beforeIdsRef.current !== null && justCreatedIdRef.current === null) {
        const newM = fresh.find((m) => !beforeIdsRef.current.has(m.id));
        if (newM) {
          beforeIdsRef.current = null;
          const st = (newM.last_status || "").toLowerCase().trim();
          if (st === "up" || st === "down") { startPopTimer(newM.id, st); }
          else { justCreatedIdRef.current = newM.id; setJustCreatedId(newM.id); }
        }
      }
      if (justCreatedIdRef.current !== null) {
        const tracked = fresh.find((m) => m.id === justCreatedIdRef.current);
        if (tracked) {
          const st = (tracked.last_status || "").toLowerCase().trim();
          if (st === "up" || st === "down") {
            const doneId = justCreatedIdRef.current;
            justCreatedIdRef.current = null; setJustCreatedId(null); startPopTimer(doneId, st);
          }
        }
      }
      setMonitors(fresh);
    } catch (err) { console.error(err); } finally { setLoading(false); }
  };

  const fetchCategories = async () => {
    try {
      const res  = await getCategories();
      const list = res?.data?.data || [];
      const hasOthers = list.some((c) => (c.name || "").toLowerCase() === "others");
      let finalList = hasOthers ? list : [SYSTEM_OTHERS, ...list];
      finalList = finalList.sort((a, b) => {
        if (a.name === "Others") return 1;
        if (b.name === "Others") return -1;
        return a.name.localeCompare(b.name);
      });
      setCategories(finalList);
    } catch (err) { console.error(err); setCategories([SYSTEM_OTHERS]); }
  };

  useEffect(() => {
    fetchMonitors(); fetchCategories();
    const mi = setInterval(fetchMonitors,   2000);
    const ci = setInterval(fetchCategories, 2000);
    return () => {
      clearInterval(mi); clearInterval(ci);
      if (popTimerRef.current) clearTimeout(popTimerRef.current);
    };
  }, []);

  const getCatStyle = (catName) => {
    const cat   = categories.find((c) => c.name === catName);
    const color = cat?.color || FALLBACK_COLORS[catName] || "gray";
    return COLOR_STYLES[color] || COLOR_STYLES.gray;
  };

  const filtered = useMemo(() => {
    let list = [...monitors];
    if (selectedCategory) list = list.filter((m) => (m.category || "Others") === selectedCategory);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((m) =>
        (m.name || "").toLowerCase().includes(q) || (m.url || "").toLowerCase().includes(q)
      );
    }
    return list;
  }, [monitors, selectedCategory, search]);

  const sorted = useMemo(() => {
    const isPinned = (m) => m.id === justCreatedId || m.id === popId;
    if (sortOrder === "up_only" || sortOrder === "down_only") {
      const target = sortOrder === "up_only" ? "up" : "down";
      return filtered.filter((m) => isPinned(m) || (m.last_status || "").toLowerCase() === target);
    }
    const list     = [...filtered];
    const rankUp   = (m) => { if (isPinned(m)) return 0; return (m.last_status || "").toLowerCase() === "up"   ? 1 : 2; };
    const rankDown = (m) => { if (isPinned(m)) return 0; return (m.last_status || "").toLowerCase() === "down" ? 1 : 2; };
    if (sortOrder === "default") return [...list.filter(isPinned), ...list.filter((m) => !isPinned(m))];
    list.sort((a, b) => {
      const ra = sortOrder === "asc" ? rankUp(a) : rankDown(a);
      const rb = sortOrder === "asc" ? rankUp(b) : rankDown(b);
      if (ra !== rb) return ra - rb;
      return (a.name || "").toLowerCase().localeCompare((b.name || "").toLowerCase());
    });
    return list;
  }, [filtered, sortOrder, justCreatedId, popId]);

  useEffect(() => {
    if (!highlightId || jumpedRef.current) return;
    const idx = sorted.findIndex((m) => m.id === highlightId);
    if (idx === -1) return;
    jumpedRef.current = true;
    setPage(Math.floor(idx / PAGE_SIZE) + 1);
  }, [highlightId, sorted]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pageRows   = sorted.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  useEffect(() => { setPage(1); }, [search, sortOrder, selectedCategory]);

  useEffect(() => {
    if (highlightId && highlightRef.current)
      setTimeout(() => highlightRef.current?.scrollIntoView({ behavior: "smooth", block: "center" }), 250);
  }, [highlightId, safePage]);

  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold text-white mb-6">My Monitors</h1>

      <div className="flex flex-col sm:flex-row gap-4 mb-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={20} />
          <input type="text" value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search monitors..."
            className="w-full pl-10 pr-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 focus:border-green-500 outline-none"/>
        </div>
        <select value={selectedCategory} onChange={(e) => handleCategory(e.target.value)}
          className="px-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 focus:border-green-500 outline-none">
          <option value="">All Categories</option>
          {categories.map((cat) => <option key={cat.id} value={cat.name}>{cat.name}</option>)}
        </select>
        <select value={sortOrder} onChange={(e) => handleSortOrder(e.target.value)}
          className="w-36 flex-shrink-0 px-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 focus:border-green-500 outline-none cursor-pointer">
          <option value="default">Default</option>
          <option value="asc">Ascending</option>
          <option value="desc">Descending</option>
          <option value="up_only">🟢 Up Only</option>
          <option value="down_only">🔴 Down Only</option>
        </select>
      </div>

      <p className="text-gray-400 text-sm mb-4">
        Showing {sorted.length} of {monitors.length} monitors
        {selectedCategory && <span className="ml-2 text-green-400">· {selectedCategory}</span>}
      </p>

      <div className="rounded-2xl border border-gray-800 bg-gradient-to-b from-gray-950 to-gray-900 shadow-lg overflow-hidden">
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full text-left">
            <thead className="sticky top-0 bg-gray-950/95 backdrop-blur border-b border-gray-800">
              <tr className="text-xs uppercase tracking-wider text-gray-400">
                <th className="px-5 py-3">Monitor</th>
                <th className="px-5 py-3">Category</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Uptime</th>
                <th className="px-5 py-3">Response</th>
                <th className="px-5 py-3">SSL</th>
                <th className="px-5 py-3 text-right">Last Check</th>
              </tr>
            </thead>
            <tbody>
              {loading && monitors.length === 0 ? (
                <tr><td className="px-5 py-6 text-gray-400" colSpan={7}>Loading monitors...</td></tr>
              ) : sorted.length === 0 ? (
                <tr><td className="px-5 py-6 text-gray-400" colSpan={7}>No monitors found</td></tr>
              ) : pageRows.map((monitor) => {
                const isChecking    = monitor.id === justCreatedId;
                const isPop         = monitor.id === popId;
                const isUp          = popStatus === "up";
                const isHighlighted = monitor.id === highlightId;
                const category      = monitor.category || "Others";
                const catStyle      = getCatStyle(category);
                const sslText = monitor.url?.startsWith("https://") && monitor.ssl_days_remaining !== null
                  ? monitor.ssl_days_remaining < 0 ? `${Math.abs(monitor.ssl_days_remaining)}d ago` : `${monitor.ssl_days_remaining}d`
                  : "—";
                const sslColor = !monitor.url?.startsWith("https://") || monitor.ssl_days_remaining === null ? "text-gray-500"
                  : monitor.ssl_days_remaining <= 7 ? "text-red-400"
                  : monitor.ssl_days_remaining <= 30 ? "text-yellow-400" : "text-green-400";
                const lastCheck = monitor.last_checked_at ? (() => {
                  const diff = Math.floor((Date.now() - new Date(monitor.last_checked_at).getTime()) / 1000);
                  if (diff < 60) return `${diff}s ago`;
                  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
                  return `${Math.floor(diff / 3600)}h ago`;
                })() : "Never";
                const rowClass = isChecking ? "bg-yellow-500/10 border-l-4 border-l-yellow-500"
                  : isPop ? (isUp ? "bg-green-500/20 border-l-4 border-l-green-400" : "bg-red-500/20 border-l-4 border-l-red-400")
                  : isHighlighted ? "bg-yellow-500/10" : "";
                return (
                  <tr key={monitor.id} ref={isHighlighted ? highlightRef : null}
                    className={`border-b border-gray-900 hover:bg-gray-900/40 transition-all duration-500 ${rowClass}`}>
                    <td className="px-5 py-4">
                      <div className={`font-semibold ${isChecking ? "text-yellow-300" : isPop ? (isUp ? "text-green-300" : "text-red-300") : isHighlighted ? "text-yellow-300" : "text-white"}`}>
                        {monitor.name}
                        {isChecking && <span className="ml-2 text-xs text-yellow-400 font-normal animate-pulse">● checking...</span>}
                        {isPop && <span className={`ml-2 text-xs font-semibold animate-pulse ${isUp ? "text-green-400" : "text-red-400"}`}>● {isUp ? "UP" : "DOWN"}</span>}
                      </div>
                      <div className="text-gray-500 text-sm truncate max-w-[520px]">{monitor.url}</div>
                    </td>
                    <td className="px-5 py-4"><span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${catStyle}`}>{category}</span></td>
                    <td className="px-5 py-4"><StatusBadge status={monitor.last_status}/></td>
                    <td className="px-5 py-4"><span className="font-semibold text-green-400">{monitor.uptime_percentage}%</span></td>
                    <td className="px-5 py-4 text-white">
                      {monitor.last_response_time_ms ? <span className="font-semibold">{monitor.last_response_time_ms}ms</span> : <span className="text-gray-500">—</span>}
                    </td>
                    <td className={`px-5 py-4 font-semibold ${sslColor}`}>
                      {monitor.url?.startsWith("https://") ? (monitor.ssl_days_remaining <= 7 ? "⚠️ " : "🔒 ") : ""}{sslText}
                    </td>
                    <td className="px-5 py-4 text-right text-white font-semibold">{lastCheck}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <PaginationCenter page={safePage} totalPages={totalPages}
          onPrev={() => setPage((p) => Math.max(1, p - 1))}
          onNext={() => setPage((p) => Math.min(totalPages, p + 1))}/>
      </div>
    </div>
  );
}