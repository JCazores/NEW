import { useState, useEffect, useCallback } from "react";
import axios from "axios";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000/api";

function MetricCard({ title, percent, used, total, unit, color }) {
  const barColor = {
    blue:   percent >= 90 ? "bg-red-500" : percent >= 70 ? "bg-yellow-500" : "bg-blue-500",
    purple: percent >= 90 ? "bg-red-500" : percent >= 70 ? "bg-yellow-500" : "bg-purple-500",
    yellow: percent >= 90 ? "bg-red-500" : percent >= 70 ? "bg-yellow-400" : "bg-yellow-500",
  }[color] || "bg-blue-500";
  const textColor = percent >= 90 ? "text-red-400" : percent >= 70 ? "text-yellow-400" : "text-blue-400";
  return (
    <div className="bg-[#1a1f2e] rounded-xl p-5 flex flex-col gap-3">
      <div className="flex justify-between text-sm text-gray-400">
        <span>{title}</span>
        {total
? <span className={textColor}>{used} / {total} {unit}</span>
          : <span className={textColor}>{percent}%</span>
        }
      </div>
      <div className={"text-3xl font-bold " + textColor}>{percent}%</div>
      {percent >= 90 && <div className="text-xs text-red-400">Critical running low</div>}
      <div className="w-full bg-gray-700 rounded-full h-1.5">
        <div className={barColor + " h-1.5 rounded-full transition-all duration-700"} style={{ width: percent + "%" }} />
      </div>
    </div>
  );
}

function ServiceGroup({ title, services }) {
  return (
    <div className="mb-4">
      <div className="text-xs text-gray-500 uppercase tracking-widest mb-2 px-1">{title}</div>
      {services.map((s) => (
        <div key={s.name} className="flex items-center justify-between py-2.5 px-3 rounded-lg hover:bg-white/5 transition">
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2.5 w-2.5">
              {s.status === "up" ? (
                <>
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-50" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-400" />
                </>
              ) : (
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500" />
              )}
            </span>
            <span className="text-white text-sm">{s.name}</span>
            <span className={"text-xs font-medium " + (s.status === "up" ? "text-green-400" : "text-red-400")}>{s.status}</span>
          </div>
          {s.latency != null && s.latency > 0 && (
            <span className="text-gray-500 text-xs">{s.latency}ms</span>
          )}
        </div>
      ))}
    </div>
  );
}

function LiveIndicator({ lastUpdated }) {
  return (
    <div className="flex items-center gap-2">
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
        <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
      </span>
      <span className="text-gray-400 text-xs">
        Live · {lastUpdated ? "Updated " + lastUpdated.toLocaleTimeString() : "Connecting..."}
      </span>
    </div>
  );
}

export default function AdminSystemHealth() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchHealth = useCallback(async () => {
    try {
      const token = localStorage.getItem("token");
      const res = await axios.get(API_BASE + "/admin/system-health", {
        headers: { Authorization: "Bearer " + token },
      });
      setData(res.data);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.response?.data?.message || err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 5000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  if (loading) return (
    <div className="flex flex-col items-center justify-center h-64 gap-3 text-gray-400">
      <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      <span className="text-sm">Fetching system health...</span>
    </div>
  );

  if (error) return (
    <div className="flex items-center justify-center h-64 text-red-400 text-sm">{error}</div>
  );

  const { cpu, memory, disk, services, queue, database, cache, api } = data || {};

  const grouped = (services || []).reduce((acc, s) => {
    if (!acc[s.group]) acc[s.group] = [];
    acc[s.group].push(s);
    return acc;
  }, {});

  const upServices   = (services || []).filter(s => s.status === "up").length;
  const downServices = (services || []).length - upServices;

  return (
    <div className="p-6 space-y-6 text-white min-h-screen bg-[#0f1117]">

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">System Health</h1>
          <p className="text-gray-400 text-sm mt-1">Real-time server metrics and service status</p>
        </div>
        <div className="flex items-center gap-4">
          <LiveIndicator lastUpdated={lastUpdated} />
          <button onClick={fetchHealth} className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-700 text-sm hover:bg-gray-800 transition">
            Refresh
          </button>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 bg-green-500/10 border border-green-500/20 text-green-400 text-xs font-medium px-3 py-1.5 rounded-full">
          {upServices} services up
        </div>
        {downServices > 0 && (
          <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-medium px-3 py-1.5 rounded-full">
            {downServices} services down
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard title="CPU Usage"    percent={cpu?.usage ?? 0}      color="blue" />
        <MetricCard title="Memory Usage" percent={memory?.percent ?? 0}  used={memory?.used_gb} total={memory?.total_gb} unit="GB" color="purple" />
        <MetricCard title="Disk Usage"   percent={disk?.percent ?? 0}    used={Math.round(disk?.used_gb)}   total={Math.round(disk?.total_gb)}   unit="GB" color="yellow" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-[#1a1f2e] rounded-xl p-5 flex flex-col">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Service Status</h2>
          <div className="overflow-y-auto max-h-72 pr-1">
            {Object.entries(grouped).map(([group, items]) => (
              <ServiceGroup key={group} title={group} services={items} />
            ))}
          </div>
        </div>

        <div className="bg-[#1a1f2e] rounded-xl p-5">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Queue and Workers</h2>
          {[
            { label: "Scan Workers",      sub: "Active / Max capacity",       value: (queue?.active_workers) + " / " + (queue?.max_workers), accent: "text-blue-400" },
            { label: "Queue Depth",       sub: "Jobs waiting to be processed", value: queue?.queue_depth,       accent: "text-blue-400" },
            { label: "Failed Jobs 24h",   sub: "Jobs that errored out",        value: queue?.failed_jobs_24h,   accent: queue?.failed_jobs_24h > 0 ? "text-red-400" : "text-green-400", showRetry: queue?.failed_jobs_24h > 0 },
            { label: "Avg Scan Duration", sub: "Past 7 days",                  value: queue?.avg_scan_duration, accent: "text-blue-400" },
          ].map(({ label, sub, value, accent, showRetry }) => (
            <div key={label} className="flex items-center justify-between py-3 border-b border-gray-800 last:border-0">
              <div>
                <div className="text-white text-sm">{label}</div>
                <div className="text-gray-500 text-xs">{sub}</div>
              </div>
              <div className="flex items-center gap-2">
                <span className={"text-lg font-semibold " + accent}>{value}</span>
                {showRetry && (
                  <button className="text-xs bg-red-900/40 text-red-400 border border-red-700 px-2 py-0.5 rounded hover:bg-red-900/60 transition">
                    Retry All
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pb-8">
        <div className="bg-[#1a1f2e] rounded-xl p-5">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Database</h2>
          {[
            ["Connection pool",   (database?.connection_pool_used) + " / " + (database?.connection_pool_max)],
            ["Query latency avg", (database?.query_latency_avg) + "ms"],
            ["Slow queries 1h",   database?.slow_queries_1h, database?.slow_queries_1h > 0 ? "text-yellow-400" : "text-gray-300"],
            ["Storage used",      (database?.storage_used_gb) + " GB"],
          ].map(([label, val, accent]) => (
            <div key={label} className="flex justify-between py-2 text-sm border-b border-gray-800 last:border-0">
              <span className="text-gray-400">{label}</span>
              <span className={accent || "text-gray-300"}>{val}</span>
            </div>
          ))}
        </div>

        <div className="bg-[#1a1f2e] rounded-xl p-5">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Cache</h2>
          {[
            ["Hit rate",     (cache?.hit_rate) + "%",  "text-green-400"],
            ["Cached items", cache?.used_memory_mb],
            ["Evicted keys", cache?.evicted_keys],
            ["Latency",      (cache?.latency_ms) + "ms"],
          ].map(([label, val, accent]) => (
            <div key={label} className="flex justify-between py-2 text-sm border-b border-gray-800 last:border-0">
              <span className="text-gray-400">{label}</span>
              <span className={accent || "text-gray-300"}>{val}</span>
            </div>
          ))}
          <button className="mt-4 w-full py-2 rounded-lg border border-gray-600 text-sm text-gray-300 hover:bg-gray-700 transition">
            Flush Cache
          </button>
        </div>

        <div className="bg-[#1a1f2e] rounded-xl p-5">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">API Performance</h2>
          {[
            ["Req per min",       api?.req_per_min,              "text-blue-400"],
            ["Avg response time", (api?.avg_response_time_ms) + "ms"],
            ["Error rate 1h",     (api?.error_rate_1h) + "%",    api?.error_rate_1h > 1 ? "text-red-400" : "text-green-400"],
            ["Uptime 30d",        (api?.uptime_30d) + "%",       "text-green-400"],
          ].map(([label, val, accent]) => (
            <div key={label} className="flex justify-between py-2 text-sm border-b border-gray-800 last:border-0">
              <span className="text-gray-400">{label}</span>
              <span className={accent || "text-gray-300"}>{val}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
